# signals.py
from django.db.models.signals import post_save
from django.dispatch import receiver
from .models import *
from decimal import Decimal

@receiver(post_save, sender=Order)
def handle_referral_reward(sender, instance, created, **kwargs):
    if created:
        referral = getattr(instance.user, "referral", None)

        if referral:  
            referrer = referral.referrer  
            referred_user = instance.user  

            # ✅ Ensure reward is only given for the first order
            if Order.objects.filter(user=referred_user).exclude(id=instance.id).exists():
                return  # Exit without giving rewards if this is not the first order

            # Find an active referral offer
            referral_offer = ReferralOffer.objects.filter(
                offer__offer_type="referral", offer__is_active=True
            ).first()

            if referral_offer:
                reward_amount = Decimal(str(referral_offer.reward_amount))  # Ensure Decimal type

                # ✅ Reward the referrer
                referrer_wallet, _ = Wallet.objects.get_or_create(user=referrer)
                referrer_wallet.balance = Decimal(str(referrer_wallet.balance)) + reward_amount
                referrer_wallet.save()

                # ✅ Reward the referred user
                referred_wallet, _ = Wallet.objects.get_or_create(user=referred_user)
                referred_wallet.balance = Decimal(str(referred_wallet.balance)) + reward_amount
                referred_wallet.save()

                # ✅ Mark the referral as "reward claimed"
                referral.reward_claimed = True
                referral.save()

                # ✅ Log the transactions for tracking
                Transaction.objects.create(
                    wallet=referrer_wallet,
                    amount=reward_amount,
                    transaction_type="Credit",
                    status="Completed",
                )

                Transaction.objects.create(
                    wallet=referred_wallet,
                    amount=reward_amount,
                    transaction_type="Credit",
                    status="Completed",
                )

                print(f"✅ Referral Reward Applied: ₹{reward_amount} to {referrer.email} & {referred_user.email}")