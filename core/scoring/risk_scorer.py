"""
Box C: Explainable Risk Scoring Engine.
Calculates a 0-100 composite risk score with complete mathematical explainability
and structured Reason Vectors strictly adhering to the CC6-IC07 Blueprint.
"""

from typing import List, Dict, Optional, Tuple
from core.models import (
    TelemetryEvent,
    RiskScore,
    ReasonFactor,
    SpecDriftStatus,
    PIISeverity,
    PIIMatch,
    AbuseAlert,
    AbuseAlertType
)


class RiskScorer:
    """
    Computes explainable weighted risk score (0-100):
    - 35% Exposure (Public unauth vs auth strength)
    - 25% PII Data Sensitivity (PAN / Aadhaar)
    - 20% Spec Drift (Shadow / Zombie Status)
    - 20% Active Anomaly & Attack Frequency
    """

    @classmethod
    def calculate_score(cls,
                        event: TelemetryEvent,
                        parameterized_path: str,
                        extracted_params: Dict[str, str],
                        spec_status: SpecDriftStatus,
                        pii_matches: List[PIIMatch],
                        pii_severity: PIISeverity,
                        abuse_alerts: List[AbuseAlert]) -> RiskScore:
        factors: List[ReasonFactor] = []
        reason_vector_items: List[str] = []

        # ---------------------------------------------------------
        # 1. Exposure (Max 35 points)
        # ---------------------------------------------------------
        exposure_pts = 0
        auth_header = event.headers.get("authorization", "") or event.headers.get("Authorization", "")
        has_bearer_jwt = "bearer" in auth_header.lower() or bool(event.jwt_sub)

        if not auth_header and not event.jwt_sub:
            exposure_pts = 35
            factors.append(ReasonFactor(
                factor="Exposure",
                points=35,
                description="+35 Unauthenticated Exposure"
            ))
            reason_vector_items.append("+35 Unauth")
        elif "basic" in auth_header.lower():
            exposure_pts = 20
            factors.append(ReasonFactor(
                factor="Exposure",
                points=20,
                description="+20 Weak Basic Authentication"
            ))
            reason_vector_items.append("+20 Weak Auth")
        else:
            # Valid token/auth
            exposure_pts = 0

        # ---------------------------------------------------------
        # 2. PII Data Sensitivity (Max 25 points)
        # ---------------------------------------------------------
        pii_pts = 0
        if pii_severity == PIISeverity.CRITICAL:
            pii_pts = 25
            crit_types = [m.entity_type for m in pii_matches if m.severity == PIISeverity.CRITICAL]
            label = "/".join(set(crit_types)) if crit_types else "PAN/Aadhaar"
            factors.append(ReasonFactor(
                factor="PII",
                points=25,
                description=f"+25 Critical PII Exposure ({label})"
            ))
            reason_vector_items.append(f"+25 PII ({label})")
        elif pii_severity == PIISeverity.SENSITIVE:
            pii_pts = 15
            sens_types = [m.entity_type for m in pii_matches if m.severity == PIISeverity.SENSITIVE]
            label = "/".join(set(sens_types)) if sens_types else "UPI/Phone"
            factors.append(ReasonFactor(
                factor="PII",
                points=15,
                description=f"+15 Sensitive PII Exposure ({label})"
            ))
            reason_vector_items.append(f"+15 PII ({label})")

        # ---------------------------------------------------------
        # 3. Spec Drift Status (Max 20 points)
        # ---------------------------------------------------------
        spec_pts = 0
        if spec_status == SpecDriftStatus.SHADOW:
            spec_pts = 20
            factors.append(ReasonFactor(
                factor="SpecDrift",
                points=20,
                description="+20 Undocumented Shadow Route"
            ))
            reason_vector_items.append("+20 Shadow")
        elif spec_status == SpecDriftStatus.ZOMBIE:
            spec_pts = 15
            factors.append(ReasonFactor(
                factor="SpecDrift",
                points=15,
                description="+15 Deprecated Zombie v1 Endpoint"
            ))
            reason_vector_items.append("+15 Zombie")

        # ---------------------------------------------------------
        # 4. Active Anomaly & Attack Frequency (Max 20 points)
        # ---------------------------------------------------------
        anomaly_pts = 0
        if abuse_alerts:
            # Check for BOLA / Token Replay / Scraping
            alert_types = set(a.alert_type for a in abuse_alerts)
            if AbuseAlertType.BOLA_IDOR in alert_types:
                anomaly_pts = 20
                factors.append(ReasonFactor(
                    factor="AbuseAnomaly",
                    points=20,
                    description="+20 BOLA / IDOR Violation"
                ))
                reason_vector_items.append("+20 BOLA")
            elif AbuseAlertType.TOKEN_REPLAY in alert_types:
                anomaly_pts = 20
                factors.append(ReasonFactor(
                    factor="AbuseAnomaly",
                    points=20,
                    description="+20 Token Replay Misuse"
                ))
                reason_vector_items.append("+20 Replay")
            elif AbuseAlertType.DATA_SCRAPING in alert_types or AbuseAlertType.BYTE_SPIKE in alert_types:
                anomaly_pts = 15
                factors.append(ReasonFactor(
                    factor="AbuseAnomaly",
                    points=15,
                    description="+15 High-Velocity Scraping / Byte Spike"
                ))
                reason_vector_items.append("+15 Scraping")

        # ---------------------------------------------------------
        # Composite Calculation (Capped at 100)
        # ---------------------------------------------------------
        raw_total = exposure_pts + pii_pts + spec_pts + anomaly_pts
        final_score = min(100, raw_total)

        # Severity categorization
        if final_score >= 85:
            severity = "CRITICAL"
        elif final_score >= 70:
            severity = "HIGH"
        elif final_score >= 40:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        # Evaluation against simulation ground truth if provided
        evaluation_label = None
        if event.ground_truth:
            is_predicted_threat = (
                final_score >= 40 
                or bool(abuse_alerts) 
                or spec_status in (SpecDriftStatus.SHADOW, SpecDriftStatus.ZOMBIE)
            )
            is_actual_attack = event.ground_truth.startswith("attack_")

            if is_actual_attack and is_predicted_threat:
                evaluation_label = "TP"
            elif not is_actual_attack and is_predicted_threat:
                evaluation_label = "FP"
            elif not is_actual_attack and not is_predicted_threat:
                evaluation_label = "TN"
            elif is_actual_attack and not is_predicted_threat:
                evaluation_label = "FN"

        return RiskScore(
            request_id=event.request_id,
            risk_score=final_score,
            severity=severity,
            reason_vector=reason_vector_items,
            factors=factors,
            parameterized_path=parameterized_path,
            extracted_params=extracted_params,
            spec_status=spec_status,
            pii_matches=pii_matches,
            abuse_alerts=abuse_alerts,
            timestamp=event.timestamp,
            evaluation_label=evaluation_label
        )
