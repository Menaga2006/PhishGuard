"""
Email Spam Detection Model Training Script
Run this script to train the model and generate required artifacts
"""

import os
import pandas as pd
from email_spam_detector import train_model, load_artifacts

def main():
    base_path = os.path.dirname(os.path.abspath(__file__))
    csv_path = os.path.join(base_path, 'spam.csv')
    models_dir = os.path.join(base_path, 'models')
    vectorizer_path = os.path.join(models_dir, 'spam_vectorizer.joblib')
    model_path = os.path.join(models_dir, 'spam_model.joblib')
    
    print('='*60)
    print('EMAIL SPAM DETECTION MODEL TRAINING')
    print('='*60)
    
    # Check if dataset exists
    if not os.path.exists(csv_path):
        print(f'❌ ERROR: {csv_path} not found!')
        print('\nPlease create a CSV file named "spam.csv" with columns:')
        print('  - label (values: "spam" or "ham")')
        print('  - message (email/text content)')
        print('\nExample CSV format:')
        print('label,message')
        print('spam,"URGENT: Click here to claim your prize!"')
        print('ham,"Hi, how are you doing today?"')
        return
    
    print(f'\n✅ Dataset found: {csv_path}')
    
    # Check dataset preview
    try:
        df = pd.read_csv(csv_path)
        print(f'\n📊 Dataset Info:')
        print(f'  - Total records: {len(df)}')
        print(f'  - Columns: {list(df.columns)}')
        print(f'\nFirst few rows:')
        print(df.head(3).to_string())
    except Exception as e:
        print(f'❌ Error reading CSV: {e}')
        return
    
    # Train model
    print(f'\n🔄 Training model...')
    try:
        vectorizer, model = train_model(csv_path, vectorizer_path, model_path)
        print(f'\n✅ Model training complete!')
        print(f'✅ Vectorizer saved: {vectorizer_path}')
        print(f'✅ Model saved: {model_path}')
        print('\n✅ You can now use the Email Spam Detection feature!')
    except Exception as e:
        print(f'❌ Training failed: {e}')
        import traceback
        traceback.print_exc()


if __name__ == '__main__':
    main()
