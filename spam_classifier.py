import pickle
import os
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, classification_report
import numpy as np

class SpamClassifier:
    def __init__(self):
        self.vectorizer = None
        self.classifier = None
        self.model_path = 'models/spam_classifier.pkl'
        self.vectorizer_path = 'models/tfidf_vectorizer.pkl'

    def create_sample_dataset(self):
        """Create a sample dataset for demonstration purposes."""
        # Sample spam emails
        spam_emails = [
            "URGENT: Your account has been suspended. Click here to verify: http://fakebank.com/verify",
            "WIN A FREE IPHONE! Enter your details now: http://prize-winner.com/claim",
            "Congratulations! You've won $1,000,000! Send your bank details to claim: http://lottery-win.com",
            "Password reset required. Your account will be deleted in 24 hours: http://security-alert.com/reset",
            "FREE MONEY! Transfer funds to your account instantly: http://cash-transfer.com",
            "Important: Your package is waiting. Pay shipping fee: http://delivery-service.com/pay",
            "Bank alert: Unusual activity detected. Verify identity: http://secure-bank.com/verify",
            "Get rich quick! Invest in our amazing opportunity: http://investment-scheme.com",
            "Your computer is infected! Download antivirus now: http://virus-removal.com/download",
            "Exclusive offer: 90% off luxury watches. Limited time: http://luxury-deals.com/buy"
        ]

        # Sample ham (non-spam) emails
        ham_emails = [
            "Hi John, let's meet for lunch tomorrow at 12pm. Best regards, Sarah",
            "Meeting reminder: Project review at 3pm in conference room B",
            "Thank you for your email. I'll review the document and get back to you by Friday",
            "Please find attached the quarterly report for Q1 2024",
            "Team, the server maintenance is scheduled for this weekend",
            "Hi, I wanted to follow up on our conversation from yesterday",
            "Can you please send me the updated requirements document?",
            "The project deadline has been extended to next month",
            "Thanks for the feedback on the presentation",
            "Let's schedule a call to discuss the new features"
        ]

        # Create labels (1 for spam, 0 for ham)
        spam_labels = [1] * len(spam_emails)
        ham_labels = [0] * len(ham_emails)

        # Combine emails and labels
        emails = spam_emails + ham_emails
        labels = spam_labels + ham_labels

        return emails, labels

    def train(self, emails=None, labels=None):
        """Train the spam classifier."""
        if emails is None or labels is None:
            emails, labels = self.create_sample_dataset()

        # Split the data
        X_train, X_test, y_train, y_test = train_test_split(
            emails, labels, test_size=0.2, random_state=42
        )

        # Create TF-IDF vectorizer
        self.vectorizer = TfidfVectorizer(max_features=5000, stop_words='english')
        X_train_tfidf = self.vectorizer.fit_transform(X_train)

        # Train Multinomial Naive Bayes classifier
        self.classifier = MultinomialNB()
        self.classifier.fit(X_train_tfidf, y_train)

        # Evaluate on test set
        X_test_tfidf = self.vectorizer.transform(X_test)
        y_pred = self.classifier.predict(X_test_tfidf)
        accuracy = accuracy_score(y_test, y_pred)

        print(f"Model trained with accuracy: {accuracy:.2f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred, target_names=['Ham', 'Spam']))

        # Save the model
        self.save_model()

        return accuracy

    def predict(self, email_text):
        """Predict if an email is spam or not."""
        if self.classifier is None or self.vectorizer is None:
            self.load_model()

        # Transform the email text
        email_tfidf = self.vectorizer.transform([email_text])

        # Get prediction and probability
        prediction = self.classifier.predict(email_tfidf)[0]
        probabilities = self.classifier.predict_proba(email_tfidf)[0]

        # Return result
        label = "spam" if prediction == 1 else "not spam"
        confidence = probabilities[prediction]

        return {
            'label': label,
            'probability': confidence,
            'spam_probability': probabilities[1],
            'ham_probability': probabilities[0]
        }

    def save_model(self):
        """Save the trained model and vectorizer."""
        os.makedirs('models', exist_ok=True)

        with open(self.model_path, 'wb') as f:
            pickle.dump(self.classifier, f)

        with open(self.vectorizer_path, 'wb') as f:
            pickle.dump(self.vectorizer, f)

        print("Model saved successfully.")

    def load_model(self):
        """Load the trained model and vectorizer."""
        try:
            with open(self.model_path, 'rb') as f:
                self.classifier = pickle.load(f)

            with open(self.vectorizer_path, 'rb') as f:
                self.vectorizer = pickle.load(f)

            print("Model loaded successfully.")
        except FileNotFoundError:
            print("Model files not found. Please train the model first.")
            return False
        return True

    def highlight_suspicious_words(self, text):
        """Highlight suspicious words in the text."""
        suspicious_words = ['free', 'urgent', 'win', 'prize', 'congratulations', 'password',
                           'account', 'verify', 'click here', 'limited time', 'exclusive',
                           'guaranteed', 'risk-free', 'act now', "don't miss"]

        highlighted_text = text
        for word in suspicious_words:
            # Case-insensitive replacement with highlighting
            import re
            pattern = re.compile(re.escape(word), re.IGNORECASE)
            highlighted_text = pattern.sub(f"**{word.upper()}**", highlighted_text)

        return highlighted_text

    def extract_links(self, text):
        """Extract links from email text."""
        import re
        url_pattern = r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'
        urls = re.findall(url_pattern, text)
        return urls