import pandas as pd
import joblib

from sklearn.model_selection import train_test_split
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)

print("=" * 50)
print("Loading dataset...")
print("=" * 50)

# Load dataset
data = pd.read_csv("../Dataset/phishing_site_urls.csv")

print(f"Total URLs: {len(data)}")
print("\nClass Distribution:")
print(data["Label"].value_counts())

# -----------------------------
# OPTIONAL:
# Uncomment the next line if you want
# to train quickly on only 50,000 URLs.
#
# data = data.sample(n=50000, random_state=42)
# -----------------------------

# Remove missing values
data = data.dropna()

# Normalize URLs
data["URL"] = (
    data["URL"]
    .str.lower()
    .str.replace("https://", "", regex=False)
    .str.replace("http://", "", regex=False)
    .str.replace("www.", "", regex=False)
)

X = data["URL"]
y = data["Label"]

print("\nConverting URLs to TF-IDF features...")

vectorizer = TfidfVectorizer(
    analyzer="char",
    ngram_range=(3, 5),
    lowercase=True,
    min_df=2
)

X = vectorizer.fit_transform(X)

print("Splitting dataset...")

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print("Training Linear SVM...")

model = LinearSVC(
    random_state=42,
    max_iter=10000
)

model.fit(X_train, y_train)

print("Training completed!")

print("\nTesting model...")

predictions = model.predict(X_test)

accuracy = accuracy_score(y_test, predictions)

print("\n" + "=" * 50)
print(f"Accuracy : {accuracy * 100:.2f}%")
print("=" * 50)

print("\nClassification Report:\n")
print(classification_report(y_test, predictions))

print("\nConfusion Matrix:\n")
print(confusion_matrix(y_test, predictions))

# Save files
joblib.dump(model, "svm_model.pkl")
joblib.dump(vectorizer, "vectorizer.pkl")

print("\nModel saved successfully!")
print("Created:")
print("   svm_model.pkl")
print("   vectorizer.pkl")