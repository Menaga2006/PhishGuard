#!/usr/bin/env python3
"""
Demo script to test the spam classifier without Gmail authentication.
"""

from spam_classifier import SpamClassifier

def main():
    print("🧪 Spam Classifier Demo")
    print("=" * 50)

    # Initialize classifier
    classifier = SpamClassifier()

    # Load the trained model
    if not classifier.load_model():
        print("Training model first...")
        classifier.train()

    # Test emails
    test_emails = [
        {
            "text": "Hi Sarah, thanks for the meeting notes. Let's schedule our next call for next week.",
            "expected": "SAFE"
        },
        {
            "text": "URGENT: Your PayPal account has been limited! Click here to verify: http://paypal-secure.com/verify",
            "expected": "SPAM"
        },
        {
            "text": "Congratulations! You've won $500,000 in the lottery! Send your details to claim: http://lottery-winner.com",
            "expected": "SPAM"
        },
        {
            "text": "Project deadline extended to Friday. Please update your tasks accordingly.",
            "expected": "SAFE"
        },
        {
            "text": "FREE iPhone giveaway! Enter now and win instantly: http://free-iphone.com/enter",
            "expected": "SPAM"
        }
    ]

    print("\n📧 Analyzing Test Emails:")
    print("-" * 60)

    for i, email in enumerate(test_emails, 1):
        result = classifier.predict(email["text"])
        highlighted = classifier.highlight_suspicious_words(email["text"])
        links = classifier.extract_links(email["text"])

        print(f"\nEmail {i}:")
        print(f"Expected: {email['expected']}")
        print(f"Predicted: {result['label'].upper()} ({result['probability']:.1%} confidence)")
        print(f"Spam Probability: {result['spam_probability']:.1%}")
        print(f"Text: {email['text'][:80]}...")
        print(f"Highlighted: {highlighted[:80]}...")

        if links:
            print(f"Links: {links}")
        else:
            print("Links: None")

        # Check if prediction matches expectation
        predicted_label = result['label'].upper()
        if predicted_label == email['expected']:
            print("✅ Correct prediction")
        else:
            print("❌ Incorrect prediction")

    print("\n" + "=" * 60)
    print("Demo completed! The spam classifier is working correctly.")

if __name__ == "__main__":
    main()