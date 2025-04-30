import re
import string
from getpass import getpass

class PasswordAnalyzer:
    def __init__(self):
        self.common_passwords = self.load_common_passwords()

    def load_common_passwords(self, filename='common_passwords.txt'):
        try:
            with open(filename, 'r') as f:
                return {line.strip() for line in f}
        except FileNotFoundError:
            return {'password', '123456', 'qwerty', 'letmein', 'admin'}

    def analyze(self, password):
        # Reset state
        self.strength_feedback = []
        self.weaknesses = []
        self.recommendations = []

        self._check_length(password)
        self._check_character_variety(password)
        self._check_common_password(password)
        self._check_sequences(password)
        self._check_repeats(password)
        # self._check_personal_info(password, ['john', '1985'])  # Optional

        self._generate_recommendations()

        return {
            'strength': self._calculate_strength(),
            'weaknesses': self.weaknesses,
            'recommendations': self.recommendations
        }

    def _check_length(self, password):
        length = len(password)
        if length < 8:
            self.weaknesses.append("Very short (less than 8 characters)")
            self.strength_feedback.append(-2)
        elif length < 12:
            self.weaknesses.append("Could be longer (12+ characters recommended)")
            self.strength_feedback.append(-1)
        else:
            self.strength_feedback.append(1)

    def _check_character_variety(self, password):
        criteria = {
            'lowercase': string.ascii_lowercase,
            'uppercase': string.ascii_uppercase,
            'digits': string.digits,
            'special': string.punctuation
        }

        present_types = sum(
            1 for chars in criteria.values()
            if any(c in chars for c in password)
        )

        if present_types < 3:
            self.weaknesses.append(f"Limited character variety ({present_types} types)")
            self.strength_feedback.append(-1)
        else:
            self.strength_feedback.append(1)

    def _check_common_password(self, password):
        if password.lower() in self.common_passwords:
            self.weaknesses.append("Commonly used password")
            self.strength_feedback.append(-2)

    def _check_sequences(self, password):
        # Check for numeric and alphabetic sequences
        for seq in ["0123456789", "abcdefghijklmnopqrstuvwxyz", "qwertyuiop", "asdfghjkl", "zxcvbnm"]:
            for i in range(len(seq) - 2):
                pattern = seq[i:i+3]
                if pattern in password.lower():
                    self.weaknesses.append(f"Contains sequence: {pattern}")
                    self.strength_feedback.append(-1)
                    break

    def _check_repeats(self, password):
        if re.search(r'(.)\1{2,}', password):  # 3+ repeating characters
            self.weaknesses.append("Repeating characters")
            self.strength_feedback.append(-1)

    # Optional: Check for personal info usage
    def _check_personal_info(self, password, personal_info):
        for item in personal_info:
            if item.lower() in password.lower():
                self.weaknesses.append("Contains personal information")
                self.strength_feedback.append(-2)

    def _calculate_strength(self):
        score = sum(self.strength_feedback)
        if score < 0:
            return "Weak"
        elif score < 2:
            return "Medium"
        return "Strong"

    def _generate_recommendations(self):
        suggestions = {
            'length': "Use passwords with at least 12 characters.",
            'variety': "Combine uppercase & lowercase letters, numbers, and symbols.",
            'common': "Avoid common words and predictable patterns.",
            'repeats': "Avoid repeating characters.",
            'personal': "Don't use personal information.",
            'manager': "Use a password manager to generate/store passwords.",
            '2fa': "Enable two-factor authentication where available."
        }

        if any("short" in w.lower() or "longer" in w.lower() for w in self.weaknesses):
            self.recommendations.append(suggestions['length'])
        if any("character variety" in w.lower() for w in self.weaknesses):
            self.recommendations.append(suggestions['variety'])
        if "Commonly used password" in self.weaknesses:
            self.recommendations.append(suggestions['common'])
        if "Repeating characters" in self.weaknesses:
            self.recommendations.append(suggestions['repeats'])
        if "Contains personal information" in self.weaknesses:
            self.recommendations.append(suggestions['personal'])

        self.recommendations.extend([
            suggestions['manager'],
            suggestions['2fa']
        ])

if __name__ == "__main__":
    analyzer = PasswordAnalyzer()
    print("🔐 Password Strength Analyzer 🔐")
    password = input("Enter password to analyze: ")

    if not password:
        print("❌ Error: No password entered.")
    else:
        result = analyzer.analyze(password)
        print("\n🔎 Security Assessment:")
        print(f"Strength: {result['strength']}")

        if result['weaknesses']:
            print("\n⚠️ Weaknesses Found:")
            for weakness in result['weaknesses']:
                print(f"- {weakness}")

        print("\n✅ Recommendations:")
        for rec in result['recommendations']:
            print(f"- {rec}")
