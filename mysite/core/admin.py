from django.contrib import admin
from django.conf import settings
from django.core.mail import send_mail
from django.utils import timezone

from .models import AIRequestLog, APIToken, NetworkLab, ProSubscription, Task, ZaadPaymentRequest


def _send_zaad_review_email(payment: ZaadPaymentRequest, approved: bool) -> None:
	if not payment.owner or not getattr(payment.owner, "email", ""):
		return

	status_text = "approved" if approved else "rejected"
	subject = f"Your Zaad payment request was {status_text}"
	body_lines = [
		f"Hello {payment.owner.username},",
		"",
		f"Your Zaad payment request ({payment.reference}) has been {status_text}.",
		f"Channel: {payment.get_payment_channel_display()} | Receiver: {payment.recipient_account}",
	]

	if approved:
		body_lines.extend([
			"Your Pro subscription is now active.",
		])
	else:
		body_lines.extend([
			"Please verify your transaction details and submit again if needed.",
		])

	if payment.review_note:
		body_lines.extend([
			"",
			f"Admin note: {payment.review_note}",
		])

	body_lines.extend([
		"",
		"Thank you.",
	])

	send_mail(
		subject=subject,
		message="\n".join(body_lines),
		from_email=settings.DEFAULT_FROM_EMAIL,
		recipient_list=[payment.owner.email],
		fail_silently=True,
	)


@admin.register(Task)
class TaskAdmin(admin.ModelAdmin):
	list_display = ("title", "is_done", "created_at")
	list_filter = ("is_done", "created_at")
	search_fields = ("title", "description")


@admin.register(NetworkLab)
class NetworkLabAdmin(admin.ModelAdmin):
	list_display = ("name", "owner", "difficulty", "protocols", "routers", "switches", "pcs", "created_at")
	list_filter = ("difficulty", "created_at")
	search_fields = ("name", "protocols", "ip_scheme")


@admin.register(AIRequestLog)
class AIRequestLogAdmin(admin.ModelAdmin):
	list_display = ("owner", "model_name", "provider", "cache_hit", "response_ms", "created_at")
	list_filter = ("provider", "model_name", "cache_hit", "created_at")
	search_fields = ("owner__username", "prompt_hash", "prompt_text")


@admin.register(APIToken)
class APITokenAdmin(admin.ModelAdmin):
	list_display = ("owner", "name", "is_active", "created_at")
	list_filter = ("is_active", "created_at")
	search_fields = ("owner__username", "name", "key")


@admin.register(ProSubscription)
class ProSubscriptionAdmin(admin.ModelAdmin):
	list_display = ("owner", "plan_name", "status", "current_period_end", "updated_at")
	list_filter = ("status", "plan_name", "updated_at")
	search_fields = ("owner__username", "stripe_customer_id", "stripe_subscription_id")


@admin.register(ZaadPaymentRequest)
class ZaadPaymentRequestAdmin(admin.ModelAdmin):
	list_display = ("owner", "payment_channel", "recipient_account", "reference", "amount", "currency", "status", "created_at", "reviewed_at")
	list_filter = ("status", "currency", "created_at")
	search_fields = ("owner__username", "reference", "sender_phone", "recipient_account")
	actions = ("approve_requests", "reject_requests")

	@admin.action(description="Approve selected Zaad requests and activate Pro")
	def approve_requests(self, request, queryset):
		now = timezone.now()
		approved_count = 0
		for payment in queryset.select_related("owner"):
			payment.status = ZaadPaymentRequest.STATUS_APPROVED
			payment.reviewed_by = request.user
			payment.reviewed_at = now
			payment.save(update_fields=["status", "reviewed_by", "reviewed_at", "updated_at"])

			subscription, _ = ProSubscription.objects.get_or_create(owner=payment.owner)
			subscription.status = ProSubscription.STATUS_ACTIVE
			subscription.plan_name = "pro_zaad_manual"
			subscription.last_payment_at = now
			subscription.save()
			_send_zaad_review_email(payment, approved=True)
			approved_count += 1

		self.message_user(request, f"Approved {approved_count} request(s) and activated Pro.")

	@admin.action(description="Reject selected Zaad requests")
	def reject_requests(self, request, queryset):
		now = timezone.now()
		rejected_count = 0
		for payment in queryset.select_related("owner"):
			payment.status = ZaadPaymentRequest.STATUS_REJECTED
			payment.reviewed_by = request.user
			payment.reviewed_at = now
			payment.save(update_fields=["status", "reviewed_by", "reviewed_at", "updated_at"])
			_send_zaad_review_email(payment, approved=False)
			rejected_count += 1
		self.message_user(request, f"Rejected {rejected_count} request(s).")
