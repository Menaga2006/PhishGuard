"""
Email Spam Detection - Complete Training Script
This script trains the ML model and saves artifacts (model.pkl, vectorizer.pkl)
Run this once: python train.py
"""

import os
import pickle
import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import re

# Configuration
DATASET_PATH = 'spam.csv'
MODEL_PATH = 'model.pkl'
VECTORIZER_PATH = 'vectorizer.pkl'
OUTPUT_DIR = '.'


def clean_text(text):
    """Clean email text."""
    if not isinstance(text, str):
        return ''
    text = text.lower()
    text = re.sub(r'http[s]?://\S+|www\.\S+', ' ', text)
    text = re.sub(r'[^a-z\s]', ' ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def load_dataset(csv_path):
    """Load and preprocess dataset."""
    print(f'Loading dataset from: {csv_path}')
    
    if not os.path.exists(csv_path):
        print(f'❌ ERROR: {csv_path} not found!')
        return None
    
    df = pd.read_csv(csv_path)
    print(f'✅ Loaded {len(df)} rows')
    print(f'Columns: {list(df.columns)}')
    
    # Normalize column names
    df.columns = [col.lower().strip() for col in df.columns]
    
    # Handle different column names
    if 'label' not in df.columns:
        print('❌ ERROR: "label" column not found')
        return None
    
    if 'message' in df.columns:
        text_col = 'message'
    elif 'text' in df.columns:
        text_col = 'text'
    else:
        print('❌ ERROR: "message" or "text" column not found')
        return None
    
    # Keep only needed columns
    df = df[['label', text_col]].rename(columns={text_col: 'message'})
    
    # Remove NaN values
    df = df.dropna(subset=['label', 'message']).reset_index(drop=True)
    
    # Normalize labels
    df['label'] = df['label'].astype(str).str.strip().str.lower()
    df['label'] = df['label'].map(lambda x: 1 if x == 'spam' else 0)
    
    # Clean text
    df['message'] = df['message'].astype(str).apply(clean_text)
    
    print(f'✅ After preprocessing: {len(df)} rows')
    print(f'Label distribution: {df["label"].value_counts().to_dict()}')
    
    return df


def train_spam_detector(csv_path, model_path, vectorizer_path):
    """Train and save spam detection model."""
    
    print('\n' + '='*70)
    print('EMAIL SPAM DETECTION - MODEL TRAINING')
    print('='*70 + '\n')
    
    # Load data
    df = load_dataset(csv_path)
    if df is None or len(df) == 0:
        print('❌ Failed to load dataset')
        return False
    
    # Prepare data
    X = df['message']
    y = df['label']
    
    # Split data
    print('\n📊 Splitting data (80% train, 20% test)...')
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    print(f'✅ Training set: {len(X_train)} | Test set: {len(X_test)}')
    
    # Create vectorizer
    print('\n📝 Creating TF-IDF Vectorizer (max_features=3000)...')
    vectorizer = TfidfVectorizer(stop_words='english', max_features=3000)
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    print(f'✅ Vectorizer created with {len(vectorizer.get_feature_names_out())} features')
    
    # Train model
    print('\n🤖 Training Multinomial Naive Bayes classifier...')
    model = MultinomialNB()
    model.fit(X_train_tfidf, y_train)
    print('✅ Model trained')
    
    # Evaluate
    print('\n📈 Evaluating model...')
    y_pred = model.predict(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    
    print(f'\n✅ Accuracy: {accuracy:.4f} ({accuracy*100:.2f}%)')
    
    print('\n📊 Confusion Matrix:')
    cm = confusion_matrix(y_test, y_pred)
    print(cm)
    
    print('\n📋 Classification Report:')
    print(classification_report(y_test, y_pred, target_names=['Not Spam', 'Spam']))
    
    # Save model
    print(f'\n💾 Saving model artifacts...')
    
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    print(f'✅ Model saved: {model_path}')
    
    with open(vectorizer_path, 'wb') as f:
        pickle.dump(vectorizer, f)
    print(f'✅ Vectorizer saved: {vectorizer_path}')
    
    print('\n' + '='*70)
    print('✅ TRAINING COMPLETE!')
    print('='*70)
    print('\nYou can now use the Email Spam Detection web app.')
    print('Run: python app.py (Flask) or streamlit run app.py (Streamlit)')
    print()
    
    return True


if __name__ == '__main__':
    success = train_spam_detector(DATASET_PATH, MODEL_PATH, VECTORIZER_PATH)
    exit(0 if success else 1)
