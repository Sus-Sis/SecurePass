import joblib

model = joblib.load("svm_model.pkl")
vectorizer = joblib.load("vectorizer.pkl")

while True:
    url = input("\nEnter URL (or type exit): ")

    if url.lower() == "exit":
        break

    url = (
        url.lower()
        .replace("https://", "")
        .replace("http://", "")
        .replace("www.", "")
    )

    X = vectorizer.transform([url])

    prediction = model.predict(X)[0]

    if prediction == "good":
        print("\n✅ Safe Website")
    else:
        print("\n⚠️ Phishing Website")