# Email Spam Detection System

A comprehensive email spam detection system that uses machine learning (TF-IDF + Multinomial Naive Bayes) to analyze emails from Gmail and detect spam with probability scores.

## Features

- **Machine Learning Spam Detection**: Uses TF-IDF vectorization and Multinomial Naive Bayes classifier
- **Gmail Integration**: Connects to Gmail API to fetch and analyze emails
- **Suspicious Word Highlighting**: Highlights words like 'free', 'urgent', 'win', etc.
- **Link Detection**: Extracts and displays links found in emails
- **Streamlit Web App**: User-friendly interface for email analysis
- **Probability Scores**: Shows confidence levels for spam/ham predictions

## Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

### 2. Gmail API Setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select an existing one
3. Enable the Gmail API
4. Create credentials (OAuth 2.0 Client ID)
5. Download the `credentials.json` file and place it in the project root

### 3. Train the Model

```bash
python train_model.py
```

This will train the spam classifier on a sample dataset and save the model files.

## Usage

### Command Line Gmail Analysis

```bash
python gmail_spam_analyzer.py
```

This will authenticate with Gmail and analyze your latest 5 emails.

### Streamlit Web App

```bash
streamlit run streamlit_app.py
```

This launches a web interface where you can:
- Analyze individual emails by pasting text
- Scan your Gmail inbox for spam
- View detailed analysis with highlighted suspicious words and links

### Integration with Existing Flask App

The spam classifier is integrated into the existing `email_analysis.py` module, so it works with the current Flask application.

## Files

- `spam_classifier.py` - Core spam classification model
- `gmail_spam_analyzer.py` - Command-line Gmail analysis tool
- `streamlit_app.py` - Web interface for spam detection
- `train_model.py` - Script to train the model
- `models/` - Directory containing trained model files
  - `spam_classifier.pkl` - Trained classifier
  - `tfidf_vectorizer.pkl` - TF-IDF vectorizer

## Model Details

- **Algorithm**: Multinomial Naive Bayes
- **Features**: TF-IDF vectorization with 5000 features
- **Training Data**: Sample dataset with spam and legitimate emails
- **Accuracy**: ~100% on sample data (can be improved with larger datasets)

## API Usage

```python
from spam_classifier import SpamClassifier

classifier = SpamClassifier()
classifier.load_model()

result = classifier.predict("Your email text here")
print(f"Prediction: {result['label']}")
print(f"Spam Probability: {result['spam_probability']:.2%}")
```

## Enhancement Features

- **Suspicious Word Detection**: Automatically highlights words commonly found in spam
- **Link Extraction**: Identifies all URLs in email content
- **Probability Scores**: Provides confidence levels for predictions
- **Batch Processing**: Can analyze multiple emails efficiently

## Future Improvements

- Use larger, real-world email datasets for training
- Implement additional ML algorithms (SVM, Random Forest)
- Add email header analysis
- Implement real-time email monitoring
- Add user feedback system for model improvement