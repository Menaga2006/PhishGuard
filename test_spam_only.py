#!/usr/bin/env python3
"""
Quick test of spam classifier without Gmail API
"""

from spam_classifier import SpamClassifier

def main():
    print("🧪 Testing Spam Classifier (No Gmail Required)")
    print("=" * 50)

    classifier = SpamClassifier()
    if not classifier.load_model():
        print("❌ Model not found. Run 'python train_model.py' first.")
        return

    # Test emails
    test_emails = [
        "Hi John, meeting at 3pm tomorrow",
        "URGENT: Your account is suspended! Click here: http://fakebank.com",
        "Congratulations! You won $1,000,000!",
        "FREE iPhone giveaway! Claim now: http://free-stuff.com",
        "Project update: deadline extended to Friday"
    ]

    print("\n📧 Test Results:")
    print("-" * 40)

    for i, email in enumerate(test_emails, 1):
        result = classifier.predict(email)
        highlighted = classifier.highlight_suspicious_words(email)
        links = classifier.extract_links(email)

        print(f"\nEmail {i}:")
        print(f"Text: {email}")
        print(f"Prediction: {result['label'].upper()} ({result['probability']:.1%})")
        print(f"Highlighted: {highlighted}")
        if links:
            print(f"Links: {links}")

if __name__ == "__main__":
    main()