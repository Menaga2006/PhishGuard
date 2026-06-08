from spam_classifier import SpamClassifier

def analyze_email(content):
    result = {}

    # Initialize spam classifier
    classifier = SpamClassifier()
    classifier.load_model()

    # Get spam prediction
    spam_result = classifier.predict(content)

    # Keyword Detection
    suspicious_keywords = ['urgent', 'click here', 'password reset', 'bank account', 'verify your account', 'free gift', 'win prize']
    found_keywords = [k for k in suspicious_keywords if k in content.lower()]
    if found_keywords:
        result['keywords'] = f'Suspicious keywords: {", ".join(found_keywords)}'
    else:
        result['keywords'] = 'No suspicious keywords'

    # Sender Analysis (placeholder)
    result['sender'] = 'Gmail API integration needed for sender analysis'

    # Spam Classification using ML model
    result['spam'] = f"{spam_result['label'].upper()} ({spam_result['probability']:.1%} confidence)"
    result['spam_probability'] = f"{spam_result['spam_probability']:.1%}"

    # Highlight suspicious words
    result['highlighted_text'] = classifier.highlight_suspicious_words(content)

    # Extract links
    links = classifier.extract_links(content)
    result['links'] = links if links else []

    # Overall assessment
    if spam_result['label'] == 'spam' or found_keywords:
        result['overall'] = 'Potential Phishing Email'
    else:
        result['overall'] = 'Safe Email'

    return result