"""
Core fraud detection engine.
Implements various fraud detection algorithms and signal analysis.
"""
from typing import List
from urllib.parse import urlparse
import difflib
import re
from datetime import datetime, timedelta

from .models import FraudSignal, RiskLevel


class FraudDetector:
    """Main fraud detection engine."""
    
    # Known legitimate bank and payment domains
    LEGITIMATE_DOMAINS = [
        "chase.com",
        "bankofamerica.com",
        "wellsfargo.com",
        "citibank.com",
        "usbank.com",
        "pnc.com",
        "capitalone.com",
        "tdbank.com",
        "paypal.com",
        "stripe.com",
        "square.com",
        "venmo.com",
        "zelle.com",
    ]
    
    # Phishing keywords commonly used in fraudulent sites
    PHISHING_KEYWORDS = [
        "secure-login",
        "verify-account",
        "update-info",
        "suspended-account",
        "urgent-action",
        "confirm-identity",
        "security-alert",
        "account-locked",
        "verify-now",
        "immediate-action",
    ]
    
    def __init__(self):
        """Initialize the fraud detector."""
        pass
    
    def analyze_url(self, url: str) -> tuple[float, List[FraudSignal], str]:
        """
        Analyze a URL for fraud risk.
        
        Args:
            url: The URL to analyze
            
        Returns:
            Tuple of (risk_score, signals, explanation)
        """
        signals: List[FraudSignal] = []
        
        # Extract domain from URL
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Remove www. prefix for comparison
        if domain.startswith("www."):
            domain = domain[4:]
        
        # 1. URL Similarity Analysis
        similarity_signal = self._check_url_similarity(domain, url)
        signals.append(similarity_signal)
        
        # 2. Domain Age Check (placeholder - will be implemented with actual API)
        age_signal = self._check_domain_age(domain)
        signals.append(age_signal)
        
        # 3. HTTPS/SSL Validation
        ssl_signal = self._check_ssl(url)
        signals.append(ssl_signal)
        
        # 4. Keyword Pattern Detection
        keyword_signal = self._check_keywords(url)
        signals.append(keyword_signal)
        
        # Calculate overall risk score (weighted average)
        risk_score = self._calculate_risk_score(signals)
        
        # Generate explanation
        explanation = self._generate_explanation(risk_score, signals)
        
        return risk_score, signals, explanation
    
    def _check_url_similarity(self, domain: str, full_url: str) -> FraudSignal:
        """
        Check URL similarity against known legitimate domains.
        
        Returns:
            FraudSignal with similarity analysis
        """
        max_similarity = 0.0
        most_similar_domain = ""
        
        for legit_domain in self.LEGITIMATE_DOMAINS:
            # Compare domain names
            similarity = difflib.SequenceMatcher(None, domain, legit_domain).ratio()
            if similarity > max_similarity:
                max_similarity = similarity
                most_similar_domain = legit_domain
        
        # High similarity (>0.7) with different domain is suspicious
        if max_similarity > 0.7 and domain != most_similar_domain:
            score = min(100, max_similarity * 100)
            description = f"Domain '{domain}' shows {max_similarity:.1%} similarity to legitimate domain '{most_similar_domain}'"
        elif max_similarity > 0.5:
            score = max_similarity * 50  # Lower score for moderate similarity
            description = f"Domain '{domain}' shows moderate similarity to known bank domains"
        else:
            score = 0
            description = f"Domain '{domain}' does not match known bank patterns"
        
        return FraudSignal(
            name="URL Similarity",
            score=score,
            description=description
        )
    
    def _check_domain_age(self, domain: str) -> FraudSignal:
        """
        Check domain age (placeholder implementation).
        
        TODO: Integrate with WHOIS API or domain age service.
        For now, returns a neutral signal.
        """
        # Placeholder: In production, this would query a WHOIS service
        # New domains (< 6 months) are more likely to be fraudulent
        
        return FraudSignal(
            name="Domain Age",
            score=0.0,  # Placeholder - will be implemented with actual API
            description="Domain age check (not yet implemented)"
        )
    
    def _check_ssl(self, url: str) -> FraudSignal:
        """
        Check SSL/HTTPS certificate validity.
        
        TODO: Implement actual SSL certificate validation.
        For now, checks if URL uses HTTPS.
        """
        if url.startswith("https://"):
            # In production, would validate certificate
            return FraudSignal(
                name="SSL/HTTPS",
                score=0.0,
                description="URL uses HTTPS (certificate validation not yet implemented)"
            )
        else:
            return FraudSignal(
                name="SSL/HTTPS",
                score=50.0,
                description="URL does not use HTTPS - sensitive data transmission is insecure"
            )
    
    def _check_keywords(self, url: str) -> FraudSignal:
        """
        Check for phishing keywords in URL.
        """
        url_lower = url.lower()
        found_keywords = []
        
        for keyword in self.PHISHING_KEYWORDS:
            if keyword in url_lower:
                found_keywords.append(keyword)
        
        if found_keywords:
            score = min(100, len(found_keywords) * 20)
            description = f"Found suspicious keywords in URL: {', '.join(found_keywords)}"
        else:
            score = 0
            description = "No suspicious keywords detected in URL"
        
        return FraudSignal(
            name="Keyword Pattern",
            score=score,
            description=description
        )
    
    def _calculate_risk_score(self, signals: List[FraudSignal]) -> float:
        """
        Calculate overall risk score from individual signals.
        Uses weighted average with higher weight on critical signals.
        """
        if not signals:
            return 0.0
        
        # Weight different signals
        weights = {
            "URL Similarity": 0.4,
            "Domain Age": 0.3,
            "SSL/HTTPS": 0.2,
            "Keyword Pattern": 0.1,
        }
        
        weighted_sum = 0.0
        total_weight = 0.0
        
        for signal in signals:
            weight = weights.get(signal.name, 0.1)
            weighted_sum += signal.score * weight
            total_weight += weight
        
        return min(100, weighted_sum / total_weight if total_weight > 0 else 0)
    
    def _generate_explanation(self, risk_score: float, signals: List[FraudSignal]) -> str:
        """
        Generate human-readable explanation of the risk assessment.
        """
        if risk_score < 30:
            base_explanation = "This website appears to be safe based on our analysis."
        elif risk_score < 70:
            base_explanation = "This website shows some suspicious characteristics."
        else:
            base_explanation = "This website shows multiple indicators of potential fraud."
        
        # Add details from significant signals
        significant_signals = [s for s in signals if s.score > 30]
        if significant_signals:
            details = " Key concerns: " + "; ".join([s.description for s in significant_signals[:2]])
            base_explanation += details
        
        return base_explanation
    
    def get_risk_level(self, risk_score: float) -> RiskLevel:
        """
        Determine risk level from risk score.
        """
        if risk_score <= 30:
            return RiskLevel.SAFE
        elif risk_score <= 70:
            return RiskLevel.SUSPICIOUS
        else:
            return RiskLevel.DANGEROUS
    
    def get_recommendation(self, risk_level: RiskLevel) -> str:
        """
        Get user recommendation based on risk level.
        """
        if risk_level == RiskLevel.SAFE:
            return "This site appears safe. Proceed with normal caution."
        elif risk_level == RiskLevel.SUSPICIOUS:
            return "Exercise caution. Verify the website's authenticity before entering sensitive information."
        else:
            return "Do not enter any personal or financial information. Exit this site immediately and report if possible."

