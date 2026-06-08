import os
import re
import pandas as pd
import joblib
import streamlit as st
from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.naive_bayes import MultinomialNB
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report

st.set_page_config(page_title="Email Spam Detection", layout="wide", initial_sidebar_state="expanded")

STOPWORDS = {
    'a', 'about', 'above', 'after', 'again', 'against', 'all', 'am', 'an', 'and', 'any', 'are', 'as', 'at',
    'be', 'because', 'been', 'before', 'being', 'below', 'between', 'both', 'but', 'by',
    'could', 'did', 'do', 'does', 'doing', 'down', 'during',
    'each', 'few', 'for', 'from', 'further',
    'had', 'has', 'have', 'having', 'he', 'her', 'here', 'hers', 'herself', 'him', 'himself', 'his', 'how',
    'i', 'if', 'in', 'into', 'is', 'it', 'its', 'itself',
    'me', 'more', 'most', 'my', 'myself',
    'no', 'nor', 'not', 'of', 'off', 'on', 'once', 'only', 'or', 'other', 'our', 'ours', 'ourselves', 'out', 'over', 'own',
    'same', 'she', 'should', 'so', 'some', 'such',
    'than', 'that', 'the', 'their', 'theirs', 'them', 'themselves', 'then', 'there', 'these', 'they', 'this', 'those', 'through', 'to',
    'too', 'under', 'until', 'up', 'very', 'was', 'we', 'were', 'what', 'when', 'where', 'which', 'while', 'who', 'whom', 'why', 'with', 'would',
    'you', 'your', 'yours', 'yourself', 'yourselves'
}


def clean_text(text: str) -> str:
    """Clean text by removing URLs, punctuation, and stopwords."""
    if not isinstance(text, str):
        return ''
    text = text.lower()
    text = re.sub(r'http[s]?://\S+|www\.\S+', ' ', text)
    text = re.sub(r'[^a-z\s]', ' ', text)
    words = [word for word in text.split() if word and word not in STOPWORDS]
    return ' '.join(words)


def load_data(csv_path: str = 'spam.csv') -> pd.DataFrame:
    """Load and preprocess dataset."""
    if not os.path.exists(csv_path):
        raise FileNotFoundError(f'❌ Dataset file not found: {csv_path}')
    
    df = pd.read_csv(csv_path)
    df.columns = [col.lower().strip() for col in df.columns]
    
    if 'label' not in df.columns:
        raise ValueError('❌ CSV must contain a "label" column')
    if 'message' not in df.columns and 'text' not in df.columns:
        raise ValueError('❌ CSV must contain a "message" or "text" column')
    
    text_col = 'message' if 'message' in df.columns else 'text'
    df = df[['label', text_col]].rename(columns={text_col: 'message'})
    df = df.dropna(subset=['label', 'message']).reset_index(drop=True)
    df['label'] = df['label'].astype(str).str.strip().str.lower().map(lambda x: 1 if x == 'spam' else 0)
    df['message'] = df['message'].astype(str).apply(clean_text)
    
    return df


def build_vectorizer() -> TfidfVectorizer:
    """Create TF-IDF vectorizer."""
    return TfidfVectorizer(stop_words='english', max_features=3000)


def train_model(csv_path: str, vectorizer_path: str, model_path: str):
    """Train and evaluate spam classifier."""
    df = load_data(csv_path)
    X = df['message']
    y = df['label']
    
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )
    
    vectorizer = build_vectorizer()
    X_train_tfidf = vectorizer.fit_transform(X_train)
    X_test_tfidf = vectorizer.transform(X_test)
    
    model = MultinomialNB()
    model.fit(X_train_tfidf, y_train)
    
    y_pred = model.predict(X_test_tfidf)
    accuracy = accuracy_score(y_test, y_pred)
    
    st.sidebar.success(f'✅ Model Accuracy: {accuracy:.4f}')
    
    with st.sidebar.expander('📊 Model Evaluation'):
        st.write('**Confusion Matrix:**')
        cm = confusion_matrix(y_test, y_pred)
        st.write(cm)
        st.write('**Classification Report:**')
        st.text(classification_report(y_test, y_pred, target_names=['Not Spam', 'Spam']))
    
    joblib.dump(vectorizer, vectorizer_path)
    joblib.dump(model, model_path)
    
    return vectorizer, model


def load_artifacts(vectorizer_path: str, model_path: str):
    """Load trained model and vectorizer."""
    if os.path.exists(vectorizer_path) and os.path.exists(model_path):
        return joblib.load(vectorizer_path), joblib.load(model_path)
    return None, None


def predict_spam(text: str, vectorizer, model) -> str:
    """Predict if message is spam or not."""
    text_clean = clean_text(text)
    if not text_clean:
        return 'Not Spam'
    features = vectorizer.transform([text_clean])
    prediction = model.predict(features)[0]
    return 'Spam' if prediction == 1 else 'Not Spam'


def main():
    base_path = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(base_path, 'spam.csv')
    vectorizer_path = os.path.join(base_path, 'tfidf_vectorizer.joblib')
    model_path = os.path.join(base_path, 'spam_model.joblib')
    
    st.title('📧 Email Spam Detection System')
    st.markdown('---')
    st.write('Enter an email or message to check if it is **Spam** or **Not Spam**.')
    st.markdown('---')
    
    vectorizer, model = load_artifacts(vectorizer_path, model_path)
    
    if vectorizer is None or model is None:
        st.info('🔄 Training model from spam.csv...')
        try:
            vectorizer, model = train_model(csv_path, vectorizer_path, model_path)
            st.success('✅ Model trained and saved successfully!')
        except Exception as e:
            st.error(f'❌ Error: {str(e)}')
            st.stop()
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        user_input = st.text_area('📝 Enter Email/Message Text:', height=200, placeholder='Paste email or message here...')
    
    with col2:
        st.write('')
        st.write('')
        predict_button = st.button('🔍 Predict', use_container_width=True)
    
    st.markdown('---')
    
    if predict_button:
        if not user_input.strip():
            st.error('❌ Please enter email text to analyze.')
        else:
            result = predict_spam(user_input, vectorizer, model)
            
            if result == 'Spam':
                st.error('🚫 **SPAM DETECTED**')
                st.markdown(f'### The message is classified as: **{result}**')
            else:
                st.success('✅ **NOT SPAM**')
                st.markdown(f'### The message is classified as: **{result}**')
    
    st.markdown('---')
    st.sidebar.markdown('### 📋 About')
    st.sidebar.write('This system uses Machine Learning to detect spam emails.')
    st.sidebar.write('- **Algorithm:** Multinomial Naive Bayes')
    st.sidebar.write('- **Feature Extraction:** TF-IDF (3000 features)')
    st.sidebar.write('- **Train/Test Split:** 80/20')


if __name__ == '__main__':
    main()
