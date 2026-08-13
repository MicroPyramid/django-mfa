from django_mfa.crypto import encrypt


def forward(Authenticator, UserOTP, UserRecoveryCodes):
    for otp in UserOTP.objects.all().iterator():
        Authenticator.objects.create(
            user_id=otp.user_id,
            type="totp",
            # migrated_from_legacy marks rows THIS migration created, so a
            # rollback can delete only those and leave post-cutover
            # enrollments alone.
            data={"secret": encrypt(otp.secret_key),
                  "migrated_from_legacy": True},
        )
        codes = list(
            UserRecoveryCodes.objects.filter(user=otp)
            .order_by("id")
            .values_list("secret_code", flat=True)
        )
        if codes:
            Authenticator.objects.create(
                user_id=otp.user_id,
                type="recovery_codes",
                # Pre-existing codes are plaintext and cannot be hashed
                # retroactively without invalidating them. Flagged so the UI can
                # prompt regeneration; hashing begins at next regeneration.
                data={"codes": codes, "used": [], "migrated_plaintext": True,
                      "migrated_from_legacy": True},
            )


def reverse(Authenticator):
    """Undo the copy.

    ``forward()`` only ever COPIED — the legacy ``UserOTP`` and
    ``UserRecoveryCodes`` rows are still present and untouched — so rolling back
    0005 means deleting the copies, not recreating originals that were never
    removed. Recreating them would hit ``IntegrityError`` on ``UserOTP.user``,
    which is a OneToOneField.

    Deletes ONLY rows this migration created, identified by the
    ``migrated_from_legacy`` marker. Rows created by ordinary enrollment after
    0005 ran carry no marker and survive a rollback — without this filter, an
    operator rolling back after any user had enrolled would silently destroy
    their MFA with no legacy row to fall back on.
    """
    Authenticator.objects.filter(
        type__in=["totp", "recovery_codes"],
        data__migrated_from_legacy=True,
    ).delete()
