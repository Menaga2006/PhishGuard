import os
import re
import argparse
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
import joblib


def clean_text(text: str) -> str:
    """Clean raw text for machine learning."""
    if not isinstance(text, str):
        return ''
    text = text.lower()
    text = re.sub(r'http[s]?://\S+', ' ', text)
    text = re.sub(r'[^a-z0-9\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def load_dataset(csv_path: str) -> pd.DataFrame:
    """Load dataset from a CSV file and normalize column names."""
    df = pd.read_csv(csv_path)
    lower_cols = [col.lower().strip() for col in df.columns]
    df.columns = lower_cols

    if 'label' not in df.columns and 'v1' in df.columns:
        df = df.rename(columns={'v1': 'label'})

    text_col = None
    if 'message' in df.columns:
        text_col = 'message'
    elif 'text' in df.columns:
        text_col = 'text'
    elif 'v2' in df.columns:
        text_col = 'v2'
    elif 'body' in df.columns:
        text_col = 'body'
    elif 'content' in df.columns:
        text_col = 'content'

    if 'label' not in df.columns:
        raise ValueError('CSV dataset must contain a "label" column (or v1 for SMS Spam dataset).')
    if text_col is None:
        raise ValueError('CSV dataset must contain a "message", "text", "v2", "body", or "content" column.')

    df = df[['label', text_col]].rename(columns={text_col: 'message'})
    df = df.dropna(subset=['label', 'message'])
    df['label'] = df['label'].astype(str).str.strip().str.lower()
    df['message_clean'] = df['message'].apply(clean_text)

    if not df['label'].isin(['spam', 'ham']).all():
        df['label'] = df['label'].map(lambda val: 'spam' if 'spam' in str(val).lower() else 'ham')

    df = df[df['label'].isin(['spam', 'ham'])].reset_index(drop=True)
    return df


def build_vectorizer() -> TfidfVectorizer:
    """Create a TF-IDF vectorizer for email text."""
    return TfidfVectorizer(stop_words='english', max_features=5000)


def build_model(model_type: str = 'naive_bayes'):
    """Create a classifier model instance."""
    if model_type == 'logistic':
        return LogisticRegression(max_iter=500)
    return MultinomialNB()


def train_model(csv_path: str, model_type: str = 'naive_bayes', test_size: float = 0.2, random_state: int = 42):
    """Train the spam classifier and return the fitted vectorizer and model."""
    df = load_dataset(csv_path)
    X = df['message_clean'].tolist()
    y = df['label'].tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=test_size, random_state=random_state, stratify=y
    )

    vectorizer = build_vectorizer()
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)

    model = build_model(model_type)
    model.fit(X_train_tfidf, y_train)

    y_pred = model.predict(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    report = classification_report(y_test, y_pred, target_names=['ham', 'spam'])
    matrix = confusion_matrix(y_test, y_pred, labels=['spam', 'ham'])

    print('Training complete.')
    print(f'Accuracy: {accuracy:.4f}')
    print('\nClassification Report:')
    print(report)
    print('\nConfusion Matrix:')
    print('labels=[spam, ham]')
    print(matrix)

    return vectorizer, model, accuracy, report, matrix


def save_artifacts(vectorizer, model, model_dir: str = 'models') -> tuple[str, str]:
    """Save the vectorizer and model to disk."""
    os.makedirs(model_dir, exist_ok=True)
    vectorizer_path = os.path.join(model_dir, 'spam_vectorizer.joblib')
    model_path = os.path.join(model_dir, 'spam_model.joblib')

    joblib.dump(vectorizer, vectorizer_path)
    joblib.dump(model, model_path)
    print(f'Saved vectorizer to: {vectorizer_path}')
    print(f'Saved model to: {model_path}')
    return vectorizer_path, model_path


def load_artifacts(model_dir: str = 'models') -> tuple[TfidfVectorizer, object]:
    """Load the trained vectorizer and model from disk."""
    vectorizer_path = os.path.join(model_dir, 'spam_vectorizer.joblib')
    model_path = os.path.join(model_dir, 'spam_model.joblib')
    if not os.path.exists(vectorizer_path) or not os.path.exists(model_path):
        raise FileNotFoundError('Model artifacts not found. Train the model first.')
    vectorizer = joblib.load(vectorizer_path)
    model = joblib.load(model_path)
    return vectorizer, model


def predict_message(text: str, vectorizer: TfidfVectorizer, model) -> dict:
    """Predict whether a single email message is spam or ham."""
    text_clean = clean_text(text)
    features = vectorizer.transform([text_clean])
    label = model.predict(features)[0]
    probabilities = model.predict_proba(features)[0]
    spam_prob = float(probabilities[list(model.classes_).index('spam')]) if 'spam' in model.classes_ else float(probabilities.max())
    return {
        'label': 'Spam' if label == 'spam' else 'Not Spam',
        'raw_label': label,
        'spam_probability': spam_prob,
        'ham_probability': float(probabilities[list(model.classes_).index('ham')]) if 'ham' in model.classes_ else 1.0 - spam_prob,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description='Train and evaluate an email spam classification model.')
    parser.add_argument('--data', required=True, help='Path to CSV dataset file with label and message columns.')
    parser.add_argument('--model', choices=['naive_bayes', 'logistic'], default='naive_bayes', help='Model type to train.')
    parser.add_argument('--save', action='store_true', help='Save trained model and vectorizer to the models directory.')

    args = parser.parse_args()

    vectorizer, model, accuracy, report, matrix = train_model(
        args.data,
        model_type=args.model,
    )

    if args.save:
        save_artifacts(vectorizer, model)

    print('\nRun the prediction function with load_artifacts() and predict_message().')


if __name__ == '__main__':
    main()
