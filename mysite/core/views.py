import json
import hashlib
import os
import time
import textwrap
import urllib.error
import urllib.request
from datetime import timedelta, timezone as dt_timezone
from functools import wraps
from typing import Optional

from django import forms
from django.conf import settings
from django.contrib.auth import login as auth_login
from django.contrib.auth import get_user_model
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.tokens import default_token_generator
from django.contrib.auth.views import LoginView
from django.contrib.auth.decorators import login_required, user_passes_test
from django.contrib import messages
from django.core.cache import cache
from django.core.mail import send_mail
from django.http import HttpResponse, JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.urls import reverse
from django.utils.encoding import force_bytes, force_str
from django.utils import timezone
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods

from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas as pdf_canvas

from .lab_engine import (
	analyze_config_audit,
	LabInput,
	analyze_error_output,
	build_mermaid_topology,
	generate_lab_payload,
	normalize_protocols,
)
from .models import AIRequestLog, NetworkLab
from .models import APIToken, ProSubscription, ZaadPaymentRequest

try:
	import stripe
except Exception:
	stripe = None


class AuthLoginView(LoginView):
	template_name = "registration/login.html"
	redirect_authenticated_user = True

	def _attempt_cache_key(self):
		username = (self.request.POST.get("username") or "").strip().lower()
		client_ip = (self.request.META.get("HTTP_X_FORWARDED_FOR") or self.request.META.get("REMOTE_ADDR") or "").split(",")[0].strip()
		return f"auth:login:attempts:{client_ip}:{username}"

	def _lock_cache_key(self):
		username = (self.request.POST.get("username") or "").strip().lower()
		client_ip = (self.request.META.get("HTTP_X_FORWARDED_FOR") or self.request.META.get("REMOTE_ADDR") or "").split(",")[0].strip()
		return f"auth:login:lock:{client_ip}:{username}"

	def post(self, request, *args, **kwargs):
		if cache.get(self._lock_cache_key()):
			form = self.get_form()
			minutes = max(1, int(getattr(settings, "LOGIN_RATE_LIMIT_LOCKOUT_SECONDS", 900) / 60))
			form.add_error(None, f"Too many attempts. Try again in about {minutes} minute(s).")
			return self.form_invalid(form)
		return super().post(request, *args, **kwargs)

	def form_valid(self, form):
		cache.delete(self._attempt_cache_key())
		cache.delete(self._lock_cache_key())
		return super().form_valid(form)

	def form_invalid(self, form):
		if self.request.method == "POST":
			attempt_key = self._attempt_cache_key()
			lock_key = self._lock_cache_key()
			attempts = int(cache.get(attempt_key, 0)) + 1
			window = int(getattr(settings, "LOGIN_RATE_LIMIT_WINDOW_SECONDS", 900))
			cache.set(attempt_key, attempts, timeout=window)

			max_attempts = int(getattr(settings, "LOGIN_RATE_LIMIT_ATTEMPTS", 5))
			if attempts >= max_attempts:
				lockout_seconds = int(getattr(settings, "LOGIN_RATE_LIMIT_LOCKOUT_SECONDS", 900))
				cache.set(lock_key, True, timeout=lockout_seconds)
				cache.delete(attempt_key)
				minutes = max(1, int(lockout_seconds / 60))
				form.add_error(None, f"Too many attempts. Account locked for about {minutes} minute(s).")

		return super().form_invalid(form)


class SignupForm(UserCreationForm):
	email = forms.EmailField(required=True)

	class Meta(UserCreationForm.Meta):
		model = get_user_model()
		fields = ("username", "email", "password1", "password2")

	def clean_email(self):
		email = self.cleaned_data["email"].strip().lower()
		User = get_user_model()
		if User.objects.filter(email__iexact=email).exists():
			raise forms.ValidationError("Email already in use.")
		return email


def _is_staff(user):
	return user.is_authenticated and user.is_staff


def _pro_payment_required() -> bool:
	return bool(getattr(settings, "PRO_FEATURES_REQUIRE_PAYMENT", True))


def _stripe_is_ready() -> bool:
	return bool(
		stripe
		and getattr(settings, "STRIPE_SECRET_KEY", "")
		and getattr(settings, "STRIPE_PRO_PRICE_ID", "")
	)


def _stripe_portal_ready() -> bool:
	return bool(stripe and getattr(settings, "STRIPE_SECRET_KEY", ""))


def _zaad_manual_enabled() -> bool:
	return bool(getattr(settings, "ZAAD_MANUAL_PAYMENT_ENABLED", True))


def _manual_payment_destinations():
	destinations = []
	zaad = getattr(settings, "PAYMENT_ZAAD_ACCOUNT", "") or getattr(settings, "ZAAD_MERCHANT_NUMBER", "")
	evc = getattr(settings, "PAYMENT_EVC_ACCOUNT", "")
	sahal = getattr(settings, "PAYMENT_SAHAL_ACCOUNT", "")
	bank_name = getattr(settings, "PAYMENT_BANK_NAME", "")
	bank_account = getattr(settings, "PAYMENT_BANK_ACCOUNT", "")

	if zaad:
		destinations.append({"code": "zaad", "label": "Zaad", "account": zaad})
	if evc:
		destinations.append({"code": "evc", "label": "EVC Plus", "account": evc})
	if sahal:
		destinations.append({"code": "sahal", "label": "Sahal", "account": sahal})
	if bank_name or bank_account:
		bank_value = " | ".join(item for item in [bank_name, bank_account] if item)
		destinations.append({"code": "bank", "label": "Bank Transfer", "account": bank_value})

	return destinations


def _stripe_value(obj, key: str, default=None):
	if obj is None:
		return default
	if isinstance(obj, dict):
		return obj.get(key, default)
	return getattr(obj, key, default)


def _get_or_create_subscription(user) -> ProSubscription:
	subscription, _ = ProSubscription.objects.get_or_create(owner=user)
	return subscription


def _user_has_active_pro(user) -> bool:
	if not user or not getattr(user, "is_authenticated", False):
		return False
	if user.is_staff:
		return True
	if not _pro_payment_required():
		return True
	subscription = ProSubscription.objects.filter(owner=user).first()
	return bool(subscription and subscription.is_active_now)


def _json_pro_required_response():
	return JsonResponse(
		{
			"error": "Pro subscription required.",
			"detail": "Upgrade to Pro to access this endpoint.",
		},
		status=402,
	)


def _check_pro_rate_limit(user, scope: str):
	if not user or not getattr(user, "is_authenticated", False):
		return None

	rules = getattr(settings, "PRO_RATE_LIMIT_RULES", {}) or {}
	scope_rule = rules.get(scope, {}) if isinstance(rules, dict) else {}

	window = max(
		1,
		int(scope_rule.get("window_seconds", getattr(settings, "PRO_RATE_LIMIT_WINDOW_SECONDS", 60))),
	)
	max_requests = max(
		1,
		int(scope_rule.get("requests", getattr(settings, "PRO_RATE_LIMIT_REQUESTS", 30))),
	)
	cache_key = f"pro:rate:{user.id}:{scope}"
	count = int(cache.get(cache_key, 0)) + 1
	cache.set(cache_key, count, timeout=window)

	if count <= max_requests:
		return None

	response = JsonResponse(
		{
			"error": "Rate limit exceeded.",
			"detail": f"Try again in about {window} seconds.",
		},
		status=429,
	)
	response["Retry-After"] = str(window)
	response["X-RateLimit-Limit"] = str(max_requests)
	response["X-RateLimit-Remaining"] = "0"
	response["X-RateLimit-Window"] = str(window)
	response["X-RateLimit-Scope"] = scope
	return response


def _apply_pro_rate_limit_headers(response, user, scope: str):
	if not user or not getattr(user, "is_authenticated", False):
		return response

	rules = getattr(settings, "PRO_RATE_LIMIT_RULES", {}) or {}
	scope_rule = rules.get(scope, {}) if isinstance(rules, dict) else {}
	window = max(
		1,
		int(scope_rule.get("window_seconds", getattr(settings, "PRO_RATE_LIMIT_WINDOW_SECONDS", 60))),
	)
	max_requests = max(
		1,
		int(scope_rule.get("requests", getattr(settings, "PRO_RATE_LIMIT_REQUESTS", 30))),
	)
	cache_key = f"pro:rate:{user.id}:{scope}"
	count = int(cache.get(cache_key, 0))
	remaining = max(0, max_requests - count)

	response["X-RateLimit-Limit"] = str(max_requests)
	response["X-RateLimit-Remaining"] = str(remaining)
	response["X-RateLimit-Window"] = str(window)
	response["X-RateLimit-Scope"] = scope
	return response


def _get_token_user(request):
	token_value = request.headers.get("X-API-Token", "").strip()
	if not token_value:
		auth_header = request.headers.get("Authorization", "").strip()
		if auth_header.lower().startswith("token "):
			token_value = auth_header[6:].strip()
		elif auth_header.lower().startswith("bearer "):
			token_value = auth_header[7:].strip()

	if not token_value:
		return None

	token = APIToken.objects.select_related("owner").filter(key=token_value, is_active=True).first()
	return token.owner if token else None


def _request_user_for_api(request):
	if request.user.is_authenticated:
		return request.user
	return getattr(request, "api_user", None)


def api_auth_required(view_func):
	@wraps(view_func)
	def _wrapped(request, *args, **kwargs):
		if request.user.is_authenticated:
			return view_func(request, *args, **kwargs)

		token_user = _get_token_user(request)
		if token_user:
			request.api_user = token_user
			return view_func(request, *args, **kwargs)

		return JsonResponse(
			{"error": "Authentication required. Use session login or API token."},
			status=401,
		)

	return _wrapped


def _lab_queryset_for_user(user):
	if user.is_staff:
		return NetworkLab.objects.all()
	return NetworkLab.objects.filter(owner=user)


def _lab_get_for_user_or_404(user, lab_id: int):
	return get_object_or_404(_lab_queryset_for_user(user), id=lab_id)


def _parse_form_data(request):
	protocols = request.POST.getlist("protocols")
	form_data = {
		"name": request.POST.get("name", "CCNA Practice Lab").strip() or "CCNA Practice Lab",
		"routers": int(request.POST.get("routers", 2)),
		"switches": int(request.POST.get("switches", 2)),
		"pcs": int(request.POST.get("pcs", 4)),
		"vlan_count": int(request.POST.get("vlan_count", 2)),
		"ip_scheme": request.POST.get("ip_scheme", "192.168.0.0/16").strip() or "192.168.0.0/16",
		"difficulty": request.POST.get("difficulty", "beginner"),
		"protocols": protocols,
	}
	return form_data


def _parse_api_payload(body: bytes):
	data = json.loads(body.decode("utf-8") or "{}")
	protocols = data.get("protocols", ["OSPF"])
	if not isinstance(protocols, list):
		protocols = ["OSPF"]

	return {
		"name": str(data.get("name", "API Lab") or "API Lab"),
		"routers": int(data.get("routers", 2)),
		"switches": int(data.get("switches", 2)),
		"pcs": int(data.get("pcs", 4)),
		"vlan_count": int(data.get("vlan_count", 2)),
		"ip_scheme": str(data.get("ip_scheme", "192.168.0.0/16") or "192.168.0.0/16"),
		"difficulty": str(data.get("difficulty", "beginner") or "beginner"),
		"protocols": protocols,
	}


def _build_lab_and_save(user, form_data: dict):
	lab_input = LabInput(**form_data)
	generated = generate_lab_payload(lab_input)
	normalized_protocols = normalize_protocols(form_data["protocols"])

	lab = NetworkLab.objects.create(
		name=form_data["name"],
		owner=user,
		routers=max(1, min(form_data["routers"], 6)),
		switches=max(1, min(form_data["switches"], 6)),
		pcs=max(2, min(form_data["pcs"], 32)),
		vlan_count=max(1, min(form_data["vlan_count"], 20)),
		ip_scheme=form_data["ip_scheme"],
		protocols=", ".join(normalized_protocols),
		difficulty=form_data["difficulty"],
		topology_text=generated["topology_text"],
		topology_diagram=generated["topology_diagram"],
		cli_config=generated["cli_config"],
		verification_steps=generated["verification_steps"],
		troubleshooting_guide=generated["troubleshooting_guide"],
		learning_notes=generated["learning_notes"],
		subnet_plan=generated["subnet_plan"],
		quiz=generated["quiz"],
		suggestions=generated["suggestions"],
	)

	generated["id"] = lab.id
	return lab, generated


def signup(request):
	if request.user.is_authenticated:
		return redirect("home")

	if request.method == "POST":
		form = SignupForm(request.POST)
		if form.is_valid():
			user = form.save(commit=False)
			user.email = form.cleaned_data["email"]
			require_verification = bool(getattr(settings, "ACCOUNT_REQUIRE_EMAIL_VERIFICATION", False))
			user.is_active = not require_verification
			user.save()

			if not require_verification:
				auth_login(request, user)
				return redirect("home")

			uid = urlsafe_base64_encode(force_bytes(user.pk))
			token = default_token_generator.make_token(user)
			activation_link = request.build_absolute_uri(
				reverse("activate_account", kwargs={"uidb64": uid, "token": token})
			)

			send_mail(
				subject="Activate your account",
				message=(
					"Welcome to Network Lab Platform.\n\n"
					"Click this link to activate your account:\n"
					f"{activation_link}\n\n"
					"If you did not create this account, ignore this email."
				),
				from_email=settings.DEFAULT_FROM_EMAIL,
				recipient_list=[user.email],
				fail_silently=False,
			)

			return render(request, "registration/signup_pending.html", {"email": user.email})
	else:
		form = SignupForm()

	return render(request, "registration/signup.html", {"form": form})


def activate_account(request, uidb64: str, token: str):
	User = get_user_model()
	user = None
	try:
		uid = force_str(urlsafe_base64_decode(uidb64))
		user = User.objects.get(pk=uid)
	except (TypeError, ValueError, OverflowError, User.DoesNotExist):
		user = None

	if user and default_token_generator.check_token(user, token):
		if not user.is_active:
			user.is_active = True
			user.save(update_fields=["is_active"])
		auth_login(request, user)
		return redirect("home")

	return render(request, "registration/activation_invalid.html")


@login_required
def home(request):
	latest_labs = _lab_queryset_for_user(request.user)[:8]
	is_pro = _user_has_active_pro(request.user)
	pro_required = _pro_payment_required()
	subscription = ProSubscription.objects.filter(owner=request.user).first()
	context = {
		"latest_labs": latest_labs,
		"generated": None,
		"is_admin": request.user.is_staff,
		"is_pro": is_pro,
		"pro_required": pro_required,
		"has_subscription_customer": bool(subscription and subscription.stripe_customer_id),
		"form_data": {
			"name": "CCNA Practice Lab",
			"routers": 2,
			"switches": 2,
			"pcs": 4,
			"vlan_count": 3,
			"ip_scheme": "192.168.0.0/16",
			"difficulty": "beginner",
			"protocols": ["OSPF", "VLAN"],
		},
	}

	if request.method == "POST":
		form_data = _parse_form_data(request)
		_, generated = _build_lab_and_save(request.user, form_data)
		context["generated"] = generated
		context["form_data"] = form_data

	return render(request, "core/home.html", context)


@login_required
def lab_list(request):
	labs = _lab_queryset_for_user(request.user)
	return render(request, "core/lab_list.html", {"labs": labs, "is_admin": request.user.is_staff})


@login_required
def download_lab(request, lab_id: int, filetype: str):
	lab = _lab_get_for_user_or_404(request.user, lab_id)
	safe_name = "".join(ch for ch in lab.name if ch.isalnum() or ch in ("-", "_", " ")).strip().replace(" ", "_")
	safe_name = safe_name or f"lab_{lab.id}"

	if filetype == "json":
		lab_input = LabInput(
			name=lab.name,
			routers=lab.routers,
			switches=lab.switches,
			pcs=lab.pcs,
			vlan_count=lab.vlan_count,
			ip_scheme=lab.ip_scheme,
			protocols=[item.strip() for item in lab.protocols.split(",") if item.strip()],
			difficulty=lab.difficulty,
		)
		data = {
			"name": lab.name,
			"routers": lab.routers,
			"switches": lab.switches,
			"pcs": lab.pcs,
			"vlan_count": lab.vlan_count,
			"ip_scheme": lab.ip_scheme,
			"protocols": lab.protocols,
			"difficulty": lab.difficulty,
			"topology_text": lab.topology_text,
			"topology_diagram": lab.topology_diagram,
			"mermaid_topology": build_mermaid_topology(lab_input),
			"cli_config": lab.cli_config,
			"verification_steps": lab.verification_steps,
			"troubleshooting_guide": lab.troubleshooting_guide,
			"learning_notes": lab.learning_notes,
			"subnet_plan": json.loads(lab.subnet_plan),
			"quiz": lab.quiz,
			"suggestions": lab.suggestions,
		}
		payload = json.dumps(data, indent=2)
		response = HttpResponse(payload, content_type="application/json")
		response["Content-Disposition"] = f'attachment; filename="{safe_name}.json"'
		return response

	if filetype == "txt":
		lab_input = LabInput(
			name=lab.name,
			routers=lab.routers,
			switches=lab.switches,
			pcs=lab.pcs,
			vlan_count=lab.vlan_count,
			ip_scheme=lab.ip_scheme,
			protocols=[item.strip() for item in lab.protocols.split(",") if item.strip()],
			difficulty=lab.difficulty,
		)
		chunks = [
			f"Lab Name: {lab.name}",
			f"Devices: {lab.routers} routers, {lab.switches} switches, {lab.pcs} PCs",
			f"Protocols: {lab.protocols}",
			"",
			"=== Topology Text ===",
			lab.topology_text,
			"",
			"=== Topology Diagram ===",
			lab.topology_diagram,
			"",
			"=== Mermaid Topology ===",
			build_mermaid_topology(lab_input),
			"",
			"=== CLI Configuration ===",
			lab.cli_config,
			"",
			"=== Verification Steps ===",
			lab.verification_steps,
			"",
			"=== Troubleshooting Guide ===",
			lab.troubleshooting_guide,
			"",
			"=== Learning Notes ===",
			lab.learning_notes,
			"",
			"=== Subnet Plan (JSON) ===",
			lab.subnet_plan,
		]
		response = HttpResponse("\n".join(chunks), content_type="text/plain")
		response["Content-Disposition"] = f'attachment; filename="{safe_name}.txt"'
		return response

	if filetype == "pdf":
		response = HttpResponse(content_type="application/pdf")
		response["Content-Disposition"] = f'attachment; filename="{safe_name}.pdf"'

		pdf = pdf_canvas.Canvas(response, pagesize=A4)
		width, height = A4
		x = 40
		y = height - 40

		def write_heading(text: str):
			nonlocal y
			pdf.setFont("Helvetica-Bold", 12)
			pdf.drawString(x, y, text)
			y -= 16

		def write_body(text: str):
			nonlocal y
			pdf.setFont("Courier", 8)
			for line in text.splitlines() or [""]:
				for wrapped in textwrap.wrap(line, width=110) or [""]:
					if y < 50:
						pdf.showPage()
						y = height - 40
						pdf.setFont("Courier", 8)
					pdf.drawString(x, y, wrapped)
					y -= 10

		write_heading(f"Lab: {lab.name}")
		write_body(f"Devices: {lab.routers} routers, {lab.switches} switches, {lab.pcs} PCs")
		write_body(f"Protocols: {lab.protocols}")
		y -= 6

		sections = [
			("Topology", lab.topology_text),
			("CLI Configuration", lab.cli_config),
			("Verification", lab.verification_steps),
			("Troubleshooting", lab.troubleshooting_guide),
			("Learning Notes", lab.learning_notes),
		]

		for title, content in sections:
			write_heading(title)
			write_body(content)
			y -= 6

		pdf.save()
		return response

	return HttpResponse("Unsupported file type", status=400)


@login_required
def error_analyzer(request):
	error_analysis = []
	config_analysis = []
	input_text = ""
	config_text = ""

	if request.method == "POST":
		input_text = request.POST.get("error_output", "").strip()
		config_text = request.POST.get("config_output", "").strip()
		if input_text:
			error_analysis = analyze_error_output(input_text)
		if config_text:
			config_analysis = analyze_config_audit(config_text)

	return render(
		request,
		"core/error_analyzer.html",
		{
			"error_analysis": error_analysis,
			"config_analysis": config_analysis,
			"input_text": input_text,
			"config_text": config_text,
		},
	)


@login_required
def topology_builder(request):
	return render(request, "core/topology_builder.html")


@login_required
@user_passes_test(_is_staff)
def admin_dashboard(request):
	today = timezone.now().date()
	start_day = today - timedelta(days=6)

	labs_by_day = []
	ai_by_day = []
	labels_by_day = []
	for day_offset in range(7):
		day = start_day + timedelta(days=day_offset)
		labels_by_day.append(day.strftime("%b %d"))
		labs_by_day.append(NetworkLab.objects.filter(created_at__date=day).count())
		ai_by_day.append(AIRequestLog.objects.filter(created_at__date=day).count())

	protocols_rollup = {
		"OSPF": NetworkLab.objects.filter(protocols__icontains="OSPF").count(),
		"VLAN": NetworkLab.objects.filter(protocols__icontains="VLAN").count(),
		"DHCP": NetworkLab.objects.filter(protocols__icontains="DHCP").count(),
		"ACL": NetworkLab.objects.filter(protocols__icontains="ACL").count(),
	}

	stats = {
		"users": request.user.__class__.objects.count(),
		"labs": NetworkLab.objects.count(),
		"labs_today": NetworkLab.objects.filter(created_at__date=today).count(),
		"ai_requests": AIRequestLog.objects.count(),
		"ai_cache_hits": AIRequestLog.objects.filter(cache_hit=True).count(),
	}
	recent_labs = NetworkLab.objects.select_related("owner").order_by("-created_at")[:15]
	return render(
		request,
		"core/admin_dashboard.html",
		{
			"stats": stats,
			"recent_labs": recent_labs,
			"chart_labels": labels_by_day,
			"chart_labs": labs_by_day,
			"chart_ai": ai_by_day,
			"chart_protocol_labels": list(protocols_rollup.keys()),
			"chart_protocol_values": list(protocols_rollup.values()),
		},
	)


@login_required
@require_http_methods(["GET", "POST"])
def ai_assistant(request):
	response_text = ""
	prompt = ""
	cache_hit = False
	request_ms = 0
	status_note = request.session.pop("billing_status_note", "")
	has_api_key = bool(request.session.get("openai_api_key") or os.environ.get("OPENAI_API_KEY"))
	is_pro = _user_has_active_pro(request.user)
	pro_required = _pro_payment_required()
	can_use_ai = is_pro or not pro_required
	subscription = ProSubscription.objects.filter(owner=request.user).first()
	zaad_enabled = _zaad_manual_enabled()
	show_stripe_upgrade_button = bool(getattr(settings, "SHOW_STRIPE_UPGRADE_BUTTON", False))
	zaad_merchant_number = getattr(settings, "ZAAD_MERCHANT_NUMBER", "")
	zaad_amount = getattr(settings, "ZAAD_PRO_AMOUNT", "5")
	zaad_currency = getattr(settings, "ZAAD_PRO_CURRENCY", "USD")
	manual_payment_options = _manual_payment_destinations()
	latest_zaad_payment = ZaadPaymentRequest.objects.filter(owner=request.user).first()

	if request.GET.get("upgraded") == "1":
		status_note = "Payment completed. Pro status is now active."

	if request.method == "POST":
		prompt = request.POST.get("prompt", "").strip()
		provided_api_key = request.POST.get("api_key", "").strip()
		if provided_api_key:
			request.session["openai_api_key"] = provided_api_key
			has_api_key = True
			status_note = "API key updated for this session."

		if request.POST.get("clear_api_key") == "1":
			request.session.pop("openai_api_key", None)
			has_api_key = bool(os.environ.get("OPENAI_API_KEY"))
			status_note = "Session API key cleared."

		if prompt and can_use_ai:
			rate_limit_response = _check_pro_rate_limit(request.user, "ai_assistant")
			if rate_limit_response:
				status_note = "Rate limit reached. Please wait and try again."
				response_text = ""
				recent_logs = AIRequestLog.objects.filter(owner=request.user)[:10]
				billing_url = reverse("pro_checkout_start")
				return render(
					request,
					"core/ai_assistant.html",
					{
						"prompt": prompt,
						"response_text": response_text,
						"cache_hit": cache_hit,
						"request_ms": request_ms,
						"status_note": status_note,
						"has_api_key": has_api_key,
						"recent_logs": recent_logs,
						"is_pro": is_pro,
						"pro_required": pro_required,
						"can_use_ai": can_use_ai,
						"show_stripe_upgrade_button": show_stripe_upgrade_button,
						"billing_url": billing_url,
						"stripe_ready": _stripe_is_ready(),
						"has_subscription_customer": bool(subscription and subscription.stripe_customer_id),
						"has_subscription": bool(subscription),
						"zaad_enabled": zaad_enabled,
						"zaad_merchant_number": zaad_merchant_number,
						"zaad_amount": zaad_amount,
						"zaad_currency": zaad_currency,
						"manual_payment_options": manual_payment_options,
						"latest_zaad_payment": latest_zaad_payment,
					},
				)

			api_key = (
				request.session.get("openai_api_key", "").strip()
				or os.environ.get("OPENAI_API_KEY", "").strip()
			)
			base_url = os.environ.get("OPENAI_BASE_URL", "https://api.openai.com/v1").rstrip("/")
			model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
			prompt_hash = hashlib.sha256(f"{model}|{prompt}".encode("utf-8")).hexdigest()

			cached = AIRequestLog.objects.filter(
				owner=request.user,
				prompt_hash=prompt_hash,
				model_name=model,
			).first()

			if cached:
				cache_hit = True
				response_text = cached.response_text
				status_note = "Returned cached response."
				AIRequestLog.objects.create(
					owner=request.user,
					prompt_hash=prompt_hash,
					prompt_text=prompt,
					response_text=response_text,
					model_name=model,
					provider="openai",
					cache_hit=True,
					response_ms=0,
				)
			else:
				start = time.perf_counter()

				if api_key:
					payload = json.dumps(
						{
							"model": model,
							"messages": [
								{"role": "system", "content": "You are a Cisco network lab assistant. Give practical, concise steps."},
								{"role": "user", "content": prompt},
							],
							"temperature": 0.2,
						}
					).encode("utf-8")

					request_obj = urllib.request.Request(
						url=f"{base_url}/chat/completions",
						data=payload,
						headers={
							"Authorization": f"Bearer {api_key}",
							"Content-Type": "application/json",
						},
						method="POST",
					)

					try:
						with urllib.request.urlopen(request_obj, timeout=30) as resp:
							body = json.loads(resp.read().decode("utf-8"))
							response_text = body.get("choices", [{}])[0].get("message", {}).get("content", "").strip()
							status_note = "Live AI response generated."
					except urllib.error.HTTPError as exc:
						detail = ""
						try:
							detail = exc.read().decode("utf-8")[:300]
						except Exception:
							detail = ""
						response_text = f"AI request failed: HTTP {exc.code}. {detail}".strip()
					except urllib.error.URLError as exc:
						response_text = f"AI request failed: {exc}."
					except Exception as exc:
						response_text = f"AI request failed: {exc}."
					if not response_text:
						response_text = "AI returned empty output. Try a more specific prompt."
				else:
					response_text = (
						"OPENAI_API_KEY not set. Add key in the form below or set environment variable OPENAI_API_KEY.\n\n"
						f"Prompt received:\n{prompt}\n\n"
						"Suggested next step: ask for 'OSPF lab with 3 routers and VLAN segmentation' to test AI mode."
					)
					status_note = "No API key found."

				request_ms = int((time.perf_counter() - start) * 1000)
				AIRequestLog.objects.create(
					owner=request.user,
					prompt_hash=prompt_hash,
					prompt_text=prompt,
					response_text=response_text,
					model_name=model,
					provider="openai",
					cache_hit=False,
					response_ms=request_ms,
				)
		elif not can_use_ai:
			status_note = "This feature is Pro-only. Click Upgrade to Pro to continue."
			response_text = ""
		else:
			if not status_note:
				status_note = "Type a prompt then click Ask AI."

	recent_logs = AIRequestLog.objects.filter(owner=request.user)[:10]
	billing_url = reverse("pro_checkout_start")
	return render(
		request,
		"core/ai_assistant.html",
		{
			"prompt": prompt,
			"response_text": response_text,
			"cache_hit": cache_hit,
			"request_ms": request_ms,
			"status_note": status_note,
			"has_api_key": has_api_key,
			"recent_logs": recent_logs,
			"is_pro": is_pro,
			"pro_required": pro_required,
			"can_use_ai": can_use_ai,
			"show_stripe_upgrade_button": show_stripe_upgrade_button,
			"billing_url": billing_url,
			"stripe_ready": _stripe_is_ready(),
			"has_subscription_customer": bool(subscription and subscription.stripe_customer_id),
			"has_subscription": bool(subscription),
			"zaad_enabled": zaad_enabled,
			"zaad_merchant_number": zaad_merchant_number,
			"zaad_amount": zaad_amount,
			"zaad_currency": zaad_currency,
			"manual_payment_options": manual_payment_options,
			"latest_zaad_payment": latest_zaad_payment,
		},
	)


@login_required
@require_http_methods(["POST"])
def pro_checkout_start(request):
	if _user_has_active_pro(request.user):
		messages.info(request, "Your Pro subscription is already active.")
		return redirect("ai_assistant")

	if not _pro_payment_required():
		messages.info(request, "Pro payment mode is currently disabled.")
		return redirect("ai_assistant")

	if not _stripe_is_ready():
		if bool(getattr(settings, "ALLOW_DEV_PRO_UPGRADE_WITHOUT_STRIPE", False)):
			subscription = _get_or_create_subscription(request.user)
			subscription.status = ProSubscription.STATUS_ACTIVE
			subscription.plan_name = "pro_dev_bypass"
			subscription.last_payment_at = timezone.now()
			subscription.save()
			request.session["billing_status_note"] = "Dev mode: Pro activated without Stripe checkout."
			return redirect("ai_assistant")

		request.session["billing_status_note"] = (
			"Stripe is not configured yet. Set STRIPE_SECRET_KEY and STRIPE_PRO_PRICE_ID in environment."
		)
		return redirect("ai_assistant")

	stripe.api_key = settings.STRIPE_SECRET_KEY
	success_url = request.build_absolute_uri(reverse("ai_assistant")) + "?upgraded=1"
	cancel_url = request.build_absolute_uri(reverse("ai_assistant"))

	try:
		session = stripe.checkout.Session.create(
			mode="subscription",
			line_items=[{"price": settings.STRIPE_PRO_PRICE_ID, "quantity": 1}],
			success_url=success_url,
			cancel_url=cancel_url,
			customer_email=(request.user.email or None),
			client_reference_id=str(request.user.id),
			metadata={"user_id": str(request.user.id), "plan": "pro_monthly"},
		)

		subscription = _get_or_create_subscription(request.user)
		subscription.stripe_checkout_session_id = _stripe_value(session, "id", "") or ""
		subscription.plan_name = "pro_monthly"
		subscription.save(update_fields=["stripe_checkout_session_id", "plan_name", "updated_at"])
		checkout_url = _stripe_value(session, "url", "")
		if not checkout_url:
			request.session["billing_status_note"] = "Stripe checkout URL was not returned."
			return redirect("ai_assistant")
		return redirect(checkout_url)
	except Exception as exc:
		request.session["billing_status_note"] = f"Unable to start checkout: {exc}"
		return redirect("ai_assistant")


@login_required
@require_http_methods(["POST"])
def pro_manage_subscription(request):
	if not _stripe_portal_ready():
		request.session["billing_status_note"] = "Stripe portal is not configured yet."
		return redirect("ai_assistant")

	subscription = ProSubscription.objects.filter(owner=request.user).first()
	if not subscription or not subscription.stripe_customer_id:
		request.session["billing_status_note"] = "No billing profile found yet. Complete upgrade first."
		return redirect("ai_assistant")

	stripe.api_key = settings.STRIPE_SECRET_KEY
	return_url = request.build_absolute_uri(reverse("ai_assistant"))

	try:
		portal = stripe.billing_portal.Session.create(
			customer=subscription.stripe_customer_id,
			return_url=return_url,
		)
		return redirect(portal.url)
	except Exception as exc:
		request.session["billing_status_note"] = f"Unable to open billing portal: {exc}"
		return redirect("ai_assistant")


@login_required
@require_http_methods(["POST"])
def zaad_payment_submit(request):
	if not _zaad_manual_enabled():
		request.session["billing_status_note"] = "Zaad payment is currently disabled."
		return redirect("ai_assistant")

	if _user_has_active_pro(request.user):
		request.session["billing_status_note"] = "Your Pro subscription is already active."
		return redirect("ai_assistant")

	reference = (request.POST.get("zaad_reference") or "").strip()
	payment_channel = (request.POST.get("payment_channel") or "").strip().lower()
	sender_phone = (request.POST.get("zaad_sender_phone") or "").strip()
	note = (request.POST.get("zaad_note") or "").strip()
	proof_link = (request.POST.get("payment_proof_link") or "").strip()
	proof_file = request.FILES.get("payment_proof_file")
	amount_raw = (request.POST.get("zaad_amount") or "").strip()
	amount_value = None
	recipient_label = ""
	recipient_account = ""

	payment_options = _manual_payment_destinations()
	selected = next((item for item in payment_options if item.get("code") == payment_channel), None)
	if not selected:
		request.session["billing_status_note"] = "Please choose payment method before submitting."
		return redirect("ai_assistant")

	recipient_label = selected.get("label", "")
	recipient_account = selected.get("account", "")

	if not reference:
		request.session["billing_status_note"] = "Please provide Zaad transaction reference."
		return redirect("ai_assistant")

	if amount_raw:
		try:
			amount_value = float(amount_raw)
		except ValueError:
			request.session["billing_status_note"] = "Amount must be a valid number."
			return redirect("ai_assistant")

	if proof_file and getattr(proof_file, "size", 0) > 5 * 1024 * 1024:
		request.session["billing_status_note"] = "Proof file is too large. Max size is 5MB."
		return redirect("ai_assistant")

	currency = getattr(settings, "ZAAD_PRO_CURRENCY", "USD")
	ZaadPaymentRequest.objects.create(
		owner=request.user,
		payment_channel=payment_channel,
		recipient_label=recipient_label,
		recipient_account=recipient_account,
		reference=reference,
		sender_phone=sender_phone,
		amount=amount_value,
		currency=currency,
		proof_file=proof_file,
		proof_link=proof_link,
		note=note,
	)
	request.session["billing_status_note"] = "Payment proof submitted. Admin review is pending."
	return redirect("ai_assistant")


def _resolve_user_for_stripe_event(event_obj: dict) -> Optional[object]:
	metadata = _stripe_value(event_obj, "metadata", {}) or {}
	user_id = _stripe_value(metadata, "user_id")
	if user_id:
		try:
			return get_user_model().objects.filter(id=int(user_id)).first()
		except (TypeError, ValueError):
			pass

	client_reference_id = _stripe_value(event_obj, "client_reference_id")
	if client_reference_id:
		try:
			return get_user_model().objects.filter(id=int(client_reference_id)).first()
		except (TypeError, ValueError):
			pass

	customer_id = _stripe_value(event_obj, "customer")
	if customer_id:
		subscription = ProSubscription.objects.filter(stripe_customer_id=customer_id).first()
		if subscription:
			return subscription.owner

	return None


def _update_subscription_from_payload(user, payload: dict, active: bool):
	if not user:
		return

	subscription = _get_or_create_subscription(user)
	period_end_raw = _stripe_value(payload, "current_period_end")
	period_end = None
	if period_end_raw:
		try:
			period_end = timezone.datetime.fromtimestamp(int(period_end_raw), tz=dt_timezone.utc)
		except (TypeError, ValueError, OSError):
			period_end = None

	subscription.status = ProSubscription.STATUS_ACTIVE if active else ProSubscription.STATUS_CANCELED
	subscription.current_period_end = period_end
	subscription.last_payment_at = timezone.now() if active else subscription.last_payment_at
	subscription.stripe_customer_id = _stripe_value(payload, "customer", "") or subscription.stripe_customer_id
	subscription.stripe_subscription_id = _stripe_value(payload, "id", "") or subscription.stripe_subscription_id
	subscription.save()


@csrf_exempt
@require_http_methods(["POST"])
def stripe_webhook(request):
	if not stripe or not getattr(settings, "STRIPE_WEBHOOK_SECRET", ""):
		return JsonResponse({"error": "Webhook not configured"}, status=400)

	payload = request.body
	signature = request.META.get("HTTP_STRIPE_SIGNATURE", "")

	try:
		event = stripe.Webhook.construct_event(payload, signature, settings.STRIPE_WEBHOOK_SECRET)
	except Exception:
		return JsonResponse({"error": "Invalid webhook signature"}, status=400)

	event_type = _stripe_value(event, "type", "")
	data = _stripe_value(event, "data", {}) or {}
	obj = _stripe_value(data, "object", {}) or {}

	if event_type == "checkout.session.completed":
		user = _resolve_user_for_stripe_event(obj)
		if user:
			subscription = _get_or_create_subscription(user)
			subscription.status = ProSubscription.STATUS_ACTIVE
			subscription.last_payment_at = timezone.now()
			subscription.stripe_customer_id = _stripe_value(obj, "customer", "") or subscription.stripe_customer_id
			subscription.stripe_subscription_id = _stripe_value(obj, "subscription", "") or subscription.stripe_subscription_id
			subscription.stripe_checkout_session_id = _stripe_value(obj, "id", "") or subscription.stripe_checkout_session_id
			subscription.save()

	elif event_type == "customer.subscription.updated":
		user = _resolve_user_for_stripe_event(obj)
		status = _stripe_value(obj, "status", "")
		is_active = status in {"active", "trialing"}
		_update_subscription_from_payload(user, obj, active=is_active)

	elif event_type == "customer.subscription.deleted":
		user = _resolve_user_for_stripe_event(obj)
		_update_subscription_from_payload(user, obj, active=False)

	return JsonResponse({"received": True})


@api_auth_required
@require_http_methods(["GET"])
def api_health(request):
	return JsonResponse({"status": "ok", "service": "core-api"})


@api_auth_required
@require_http_methods(["GET", "POST"])
def api_labs(request):
	api_user = _request_user_for_api(request)
	if not api_user:
		return JsonResponse({"error": "Authentication required."}, status=401)

	if request.method == "GET":
		labs = _lab_queryset_for_user(api_user)[:100]
		rows = [
			{
				"id": lab.id,
				"name": lab.name,
				"owner": lab.owner.username if lab.owner else None,
				"routers": lab.routers,
				"switches": lab.switches,
				"pcs": lab.pcs,
				"protocols": lab.protocols,
				"difficulty": lab.difficulty,
				"created_at": lab.created_at.isoformat(),
			}
			for lab in labs
		]
		return JsonResponse({"count": len(rows), "results": rows})

	if _pro_payment_required() and not _user_has_active_pro(api_user):
		return _json_pro_required_response()

	rate_limit_response = _check_pro_rate_limit(api_user, "api_labs_post")
	if rate_limit_response:
		return rate_limit_response

	try:
		form_data = _parse_api_payload(request.body)
	except (ValueError, json.JSONDecodeError):
		return JsonResponse({"error": "Invalid JSON payload"}, status=400)

	lab, generated = _build_lab_and_save(api_user, form_data)
	response = JsonResponse(
		{
			"id": lab.id,
			"name": lab.name,
			"created_at": lab.created_at.isoformat(),
			"generated": generated,
		},
		status=201,
	)
	return _apply_pro_rate_limit_headers(response, api_user, "api_labs_post")


@api_auth_required
@require_http_methods(["GET", "DELETE"])
def api_lab_detail(request, lab_id: int):
	api_user = _request_user_for_api(request)
	if not api_user:
		return JsonResponse({"error": "Authentication required."}, status=401)

	lab = _lab_get_for_user_or_404(api_user, lab_id)

	if request.method == "DELETE":
		if _pro_payment_required() and not _user_has_active_pro(api_user):
			return _json_pro_required_response()
		rate_limit_response = _check_pro_rate_limit(api_user, "api_lab_delete")
		if rate_limit_response:
			return rate_limit_response
		lab.delete()
		response = JsonResponse({"deleted": True, "id": lab_id})
		return _apply_pro_rate_limit_headers(response, api_user, "api_lab_delete")

	return JsonResponse(
		{
			"id": lab.id,
			"name": lab.name,
			"owner": lab.owner.username if lab.owner else None,
			"routers": lab.routers,
			"switches": lab.switches,
			"pcs": lab.pcs,
			"vlan_count": lab.vlan_count,
			"ip_scheme": lab.ip_scheme,
			"protocols": lab.protocols,
			"difficulty": lab.difficulty,
			"topology_text": lab.topology_text,
			"topology_diagram": lab.topology_diagram,
			"cli_config": lab.cli_config,
			"verification_steps": lab.verification_steps,
			"troubleshooting_guide": lab.troubleshooting_guide,
			"learning_notes": lab.learning_notes,
			"subnet_plan": json.loads(lab.subnet_plan),
			"quiz": lab.quiz,
			"suggestions": lab.suggestions,
			"created_at": lab.created_at.isoformat(),
		}
	)


@login_required
@require_http_methods(["POST"])
def api_create_token(request):
	if _pro_payment_required() and not _user_has_active_pro(request.user):
		return _json_pro_required_response()

	rate_limit_response = _check_pro_rate_limit(request.user, "api_create_token")
	if rate_limit_response:
		return rate_limit_response

	name = request.POST.get("name", "default").strip() or "default"
	token = APIToken.objects.create(owner=request.user, name=name)
	response = JsonResponse(
		{
			"id": token.id,
			"name": token.name,
			"key": token.key,
			"created_at": token.created_at.isoformat(),
		}
	)
	return _apply_pro_rate_limit_headers(response, request.user, "api_create_token")
