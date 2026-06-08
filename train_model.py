#!/usr/bin/env python3
"""
Script to train the spam classification model.
Run this script to train the model before using the Gmail analyzer or Streamlit app.
"""

from spam_classifier import SpamClassifier

def main():
    print("🔍 Training Spam Classification Model")
    print("=" * 50)

    # Initialize classifier
    classifier = SpamClassifier()

    # Train the model
    print("Training model on sample dataset...")
    accuracy = classifier.train()

    print(f"\n✅ Model trained successfully with {accuracy:.2%} accuracy!")
    print("Model files saved to 'models/' directory.")

    # Test the model with sample emails
    print("\n🧪 Testing model with sample emails:")
    print("-" * 40)

    test_emails = [
        "Hi John, let's meet for coffee tomorrow at 2pm.",
        "URGENT: Your account has been compromised! Click here to reset: http://fakebank.com",
        "Congratulations! You've won a free iPhone! Claim now: http://prize-winner.com",
        "Meeting reminder: Project status update at 3pm in room 204."
    ]

    for i, email in enumerate(test_emails, 1):
        result = classifier.predict(email)
        status = "🚨 SPAM" if result['label'] == 'spam' else "✅ SAFE"
        print(f"Email {i}: {status} ({result['probability']:.1%} confidence)")
        print(f"  Text: {email[:60]}...")
        print()

if __name__ == "__main__":
    main()