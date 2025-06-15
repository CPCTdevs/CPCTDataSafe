    @staticmethod
    def log_2fa_attempt(user_id, success, method):
        """Log tentativa de autenticação 2FA"""
        AuditLogger.log_action(
            action=f"2fa_attempt_{method}",
            user_id=user_id,
            success=success,
            details={"method": method}
        )

    @staticmethod
    def log_user_approval(user_id, auditor_id, approved):
        """Log aprovação/rejeição de usuário"""
        action = "user_approved" if approved else "user_rejected"
        AuditLogger.log_action(
            action=action,
            user_id=user_id,
            auditor_id=auditor_id,
            success=True,
            details={"approved": approved}
        ) 