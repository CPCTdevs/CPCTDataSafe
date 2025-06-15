import json
from datetime import datetime
from flask import request, current_app
from app.models.models import db, AuditLog

class AuditLogger:
    
    @staticmethod
    def get_client_ip():
        """Get real client IP considering proxy headers"""
        if request.headers.get('X-Forwarded-For'):
            return request.headers.get('X-Forwarded-For').split(',')[0].strip()
        elif request.headers.get('X-Real-IP'):
            return request.headers.get('X-Real-IP')
        return request.remote_addr
    
    @staticmethod
    def log_action(action, user_id=None, auditor_id=None, details=None, success=True):
        """Log an audit action"""
        try:
            audit_log = AuditLog(
                user_id=user_id,
                auditor_id=auditor_id,
                action=action,
                details=json.dumps(details) if details else None,
                ip_address=AuditLogger.get_client_ip(),
                user_agent=request.headers.get('User-Agent', '')[:512],
                success=success
            )
            db.session.add(audit_log)
            db.session.commit()
            
            current_app.logger.info(f"Audit: {action} - User: {user_id} - Auditor: {auditor_id} - Success: {success}")
        except Exception as e:
            current_app.logger.error(f"Failed to log audit action: {str(e)}")
    
    @staticmethod
    def log_login_attempt(user_id, success, details=None):
        """Log login attempt"""
        AuditLogger.log_action(
            action="login_attempt",
            user_id=user_id,
            details=details,
            success=success
        )
    
    @staticmethod
    def log_registration(user_id, success, details=None):
        """Log user registration attempt"""
        AuditLogger.log_action(
            action="user_registration",
            user_id=user_id,
            details=details,
            success=success
        )
    
    @staticmethod
    def log_email_verification(user_id, success, details=None):
        """Log email verification attempt"""
        AuditLogger.log_action(
            action="email_verification",
            user_id=user_id,
            details=details,
            success=success
        )
    
    @staticmethod
    def log_2fa_attempt(user_id, success, method="totp"):
        """Log 2FA verification attempt"""
        AuditLogger.log_action(
            action="2fa_verification",
            user_id=user_id,
            details={"method": method},
            success=success
        )
    
    @staticmethod
    def log_user_approval(user_id, auditor_id, approved):
        """Log user approval/rejection"""
        action = "user_approved" if approved else "user_rejected"
        AuditLogger.log_action(
            action=action,
            user_id=user_id,
            auditor_id=auditor_id,
            success=True
        )
    
    @staticmethod
    def log_2fa_setup(user_id, success):
        """Log 2FA setup attempt"""
        AuditLogger.log_action(
            action="2fa_setup",
            user_id=user_id,
            success=success
        )
    
    @staticmethod
    def log_password_change(user_id, success):
        """Log password change attempt"""
        AuditLogger.log_action(
            action="password_change",
            user_id=user_id,
            success=success
        ) 