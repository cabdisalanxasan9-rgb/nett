from django.db import models
from django.contrib.auth import get_user_model
import secrets


User = get_user_model()


def _generate_api_key():
	return secrets.token_hex(24)


class Task(models.Model):
	title = models.CharField(max_length=120)
	description = models.TextField(blank=True)
	is_done = models.BooleanField(default=False)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ["-created_at"]

	def __str__(self):
		return self.title


class NetworkLab(models.Model):
	DIFFICULTY_CHOICES = [
		("beginner", "Beginner"),
		("intermediate", "Intermediate"),
		("advanced", "Advanced"),
	]

	name = models.CharField(max_length=140)
	owner = models.ForeignKey(User, on_delete=models.CASCADE, null=True, blank=True, related_name="network_labs")
	routers = models.PositiveIntegerField(default=2)
	switches = models.PositiveIntegerField(default=2)
	pcs = models.PositiveIntegerField(default=4)
	vlan_count = models.PositiveIntegerField(default=2)
	ip_scheme = models.CharField(max_length=64, default="192.168.0.0/16")
	protocols = models.CharField(max_length=200, default="OSPF")
	difficulty = models.CharField(max_length=20, choices=DIFFICULTY_CHOICES, default="beginner")

	topology_text = models.TextField()
	topology_diagram = models.TextField()
	cli_config = models.TextField()
	verification_steps = models.TextField()
	troubleshooting_guide = models.TextField()
	learning_notes = models.TextField()
	subnet_plan = models.TextField()
	quiz = models.JSONField(default=list)
	suggestions = models.JSONField(default=list)

	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ["-created_at"]

	def __str__(self):
		return f"{self.name} ({self.created_at:%Y-%m-%d})"


class AIRequestLog(models.Model):
	owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="ai_requests")
	prompt_hash = models.CharField(max_length=64, db_index=True)
	prompt_text = models.TextField()
	response_text = models.TextField()
	model_name = models.CharField(max_length=120, default="gpt-4o-mini")
	provider = models.CharField(max_length=40, default="openai")
	cache_hit = models.BooleanField(default=False)
	response_ms = models.PositiveIntegerField(default=0)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ["-created_at"]

	def __str__(self):
		return f"{self.owner} {self.model_name} {self.created_at:%Y-%m-%d %H:%M}"


class APIToken(models.Model):
	owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="api_tokens")
	name = models.CharField(max_length=120, default="default")
	key = models.CharField(max_length=64, unique=True, db_index=True, default=_generate_api_key)
	is_active = models.BooleanField(default=True)
	created_at = models.DateTimeField(auto_now_add=True)

	class Meta:
		ordering = ["-created_at"]

	def __str__(self):
		return f"{self.owner} {self.name}"


class ProSubscription(models.Model):
	STATUS_INACTIVE = "inactive"
	STATUS_ACTIVE = "active"
	STATUS_CANCELED = "canceled"
	STATUS_CHOICES = [
		(STATUS_INACTIVE, "Inactive"),
		(STATUS_ACTIVE, "Active"),
		(STATUS_CANCELED, "Canceled"),
	]

	owner = models.OneToOneField(User, on_delete=models.CASCADE, related_name="pro_subscription")
	plan_name = models.CharField(max_length=60, default="pro_monthly")
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_INACTIVE)
	current_period_end = models.DateTimeField(null=True, blank=True)
	last_payment_at = models.DateTimeField(null=True, blank=True)
	stripe_customer_id = models.CharField(max_length=120, blank=True)
	stripe_subscription_id = models.CharField(max_length=120, blank=True, db_index=True)
	stripe_checkout_session_id = models.CharField(max_length=120, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ["-updated_at"]

	def __str__(self):
		return f"{self.owner} {self.status}"

	@property
	def is_active_now(self):
		from django.utils import timezone

		if self.status != self.STATUS_ACTIVE:
			return False
		if self.current_period_end is None:
			return True
		return self.current_period_end > timezone.now()


class ZaadPaymentRequest(models.Model):
	CHANNEL_ZAAD = "zaad"
	CHANNEL_EVC = "evc"
	CHANNEL_SAHAL = "sahal"
	CHANNEL_BANK = "bank"
	PAYMENT_CHANNEL_CHOICES = [
		(CHANNEL_ZAAD, "Zaad"),
		(CHANNEL_EVC, "EVC Plus"),
		(CHANNEL_SAHAL, "Sahal"),
		(CHANNEL_BANK, "Bank Transfer"),
	]

	STATUS_PENDING = "pending"
	STATUS_APPROVED = "approved"
	STATUS_REJECTED = "rejected"
	STATUS_CHOICES = [
		(STATUS_PENDING, "Pending"),
		(STATUS_APPROVED, "Approved"),
		(STATUS_REJECTED, "Rejected"),
	]

	owner = models.ForeignKey(User, on_delete=models.CASCADE, related_name="zaad_payment_requests")
	payment_channel = models.CharField(max_length=20, choices=PAYMENT_CHANNEL_CHOICES, default=CHANNEL_ZAAD)
	recipient_label = models.CharField(max_length=80, blank=True)
	recipient_account = models.CharField(max_length=120, blank=True)
	reference = models.CharField(max_length=80, db_index=True)
	sender_phone = models.CharField(max_length=30, blank=True)
	amount = models.DecimalField(max_digits=10, decimal_places=2, null=True, blank=True)
	currency = models.CharField(max_length=10, default="USD")
	note = models.TextField(blank=True)
	status = models.CharField(max_length=20, choices=STATUS_CHOICES, default=STATUS_PENDING)
	review_note = models.TextField(blank=True)
	reviewed_by = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="zaad_reviews")
	reviewed_at = models.DateTimeField(null=True, blank=True)
	created_at = models.DateTimeField(auto_now_add=True)
	updated_at = models.DateTimeField(auto_now=True)

	class Meta:
		ordering = ["-created_at"]

	def __str__(self):
		return f"{self.owner} {self.reference} {self.status}"
