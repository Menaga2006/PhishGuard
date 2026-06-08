import os
import streamlit as st
from email_spam_detector import predict_message, load_artifacts


def load_model_and_vectorizer():
    model_dir = os.path.join(os.path.dirname(__file__), 'models')
    try:
        vectorizer, model = load_artifacts(model_dir=model_dir)
        return vectorizer, model
    except FileNotFoundError:
        return None, None


def main():
    st.set_page_config(page_title='Email Spam Detector', page_icon='✉️', layout='centered')
    st.title('📧 Email Spam Detector')
    st.write('Enter email text below and click Predict to classify the message as Spam or Not Spam.')

    vectorizer, model = load_model_and_vectorizer()
    if vectorizer is None or model is None:
        st.warning('Model artifacts not found. Train the model first using `python email_spam_detector.py --data path/to/dataset.csv --save`.')
        st.stop()

    user_text = st.text_area('Email text', height=250, placeholder='Paste the email body or message text here...')
    if st.button('Predict'):
        if not user_text.strip():
            st.error('Please enter a message to predict.')
        else:
            result = predict_message(user_text, vectorizer, model)
            if result['label'] == 'Spam':
                st.error('🚫 Spam detected')
            else:
                st.success('✅ Not Spam')
            st.markdown('**Prediction:** ' + result['label'])
            st.markdown(f"**Spam probability:** {result['spam_probability']:.2%}")
            st.markdown(f"**Ham probability:** {result['ham_probability']:.2%}")


if __name__ == '__main__':
    main()
