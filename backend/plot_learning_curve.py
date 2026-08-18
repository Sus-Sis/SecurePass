import argparse
import json
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt

from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.svm import LinearSVC
from sklearn.model_selection import learning_curve, StratifiedKFold

def parse_args():
    parser = argparse.ArgumentParser(description="Generate Training & Validation Curves for SecurePass Linear SVM")
    parser.add_argument("--dataset_path", type=str, default="../Dataset/phishing_site_urls.csv", help="Path to CSV dataset")
    parser.add_argument("--sample_size", type=int, default=50000, help="Number of samples to use (0 for full dataset)")
    parser.add_argument("--output_image", type=str, default="learning_curve.png", help="Filename for output plot")
    parser.add_argument("--output_json", type=str, default="learning_curve_data.json", help="Filename for metric output JSON")
    parser.add_argument("--cv_folds", type=int, default=5, help="Number of Stratified CV folds")
    return parser.parse_args()

def main():
    args = parse_args()
    print("=" * 60)
    print(" SecurePass - Generating Training & Validation Learning Curves")
    print("=" * 60)

    # 1. Load dataset
    print(f"\n[1/5] Loading dataset from '{args.dataset_path}'...")
    data = pd.read_csv(args.dataset_path)
    data = data.dropna()

    if args.sample_size > 0 and len(data) > args.sample_size:
        print(f"-> Subsampling dataset to {args.sample_size:,} rows for fast curve generation...")
        data = data.sample(n=args.sample_size, random_state=42).reset_index(drop=True)
    else:
        print(f"-> Using full dataset ({len(data):,} rows)...")

    # 2. Normalize URLs (matching train_svm.py logic)
    print("\n[2/5] Cleaning and normalizing URL text...")
    data["URL"] = (
        data["URL"]
        .str.lower()
        .str.replace("https://", "", regex=False)
        .str.replace("http://", "", regex=False)
        .str.replace("www.", "", regex=False)
    )

    X_text = data["URL"]
    y = data["Label"]

    # 3. Vectorization
    print("\n[3/5] Extracting TF-IDF character n-gram features (3-5 n-grams)...")
    vectorizer = TfidfVectorizer(
        analyzer="char",
        ngram_range=(3, 5),
        lowercase=True,
        min_df=2
    )
    X = vectorizer.fit_transform(X_text)
    print(f"-> Feature matrix shape: {X.shape[0]:,} samples x {X.shape[1]:,} features")

    # 4. Compute Learning Curve
    print(f"\n[4/5] Computing Learning Curves with {args.cv_folds}-Fold Cross-Validation...")
    model = LinearSVC(random_state=42, max_iter=10000)
    
    # 8 intervals of training sizes from 10% to 100%
    train_sizes = np.linspace(0.1, 1.0, 8)
    cv = StratifiedKFold(n_splits=args.cv_folds, shuffle=True, random_state=42)

    start_time = time.time()
    train_sizes_abs, train_scores, val_scores = learning_curve(
        estimator=model,
        X=X,
        y=y,
        train_sizes=train_sizes,
        cv=cv,
        scoring="accuracy",
        n_jobs=-1,
        random_state=42
    )
    elapsed_time = time.time() - start_time
    print(f"-> Learning curve computation completed in {elapsed_time:.2f} seconds.")

    # Calculate mean and standard deviation
    train_mean = np.mean(train_scores, axis=1)
    train_std = np.std(train_scores, axis=1)
    val_mean = np.mean(val_scores, axis=1)
    val_std = np.std(val_scores, axis=1)

    train_loss_mean = 1.0 - train_mean
    val_loss_mean = 1.0 - val_mean

    # 5. Save Data & Generate Visual Plot
    print("\n[5/5] Generating and saving plots...")
    
    # Save numerical results to JSON
    json_data = {
        "sample_size": len(data),
        "cv_folds": args.cv_folds,
        "train_sizes": train_sizes_abs.tolist(),
        "train_accuracy_mean": train_mean.tolist(),
        "train_accuracy_std": train_std.tolist(),
        "val_accuracy_mean": val_mean.tolist(),
        "val_accuracy_std": val_std.tolist(),
        "final_train_accuracy": float(train_mean[-1]),
        "final_val_accuracy": float(val_mean[-1])
    }
    with open(args.output_json, "w") as f:
        json.dump(json_data, f, indent=4)
    print(f"-> Saved data to '{args.output_json}'")

    # Plot creation with professional styling
    plt.style.use("ggplot")
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(14, 5.5), dpi=300)

    # --- Subplot 1: Accuracy Curve ---
    ax1.plot(train_sizes_abs, train_mean, 'o-', color='#1f77b4', linewidth=2, label='Training Accuracy')
    ax1.fill_between(train_sizes_abs, train_mean - train_std, train_mean + train_std, alpha=0.15, color='#1f77b4')

    ax1.plot(train_sizes_abs, val_mean, 'o-', color='#ff7f0e', linewidth=2, label='Validation Accuracy')
    ax1.fill_between(train_sizes_abs, val_mean - val_std, val_mean + val_std, alpha=0.15, color='#ff7f0e')

    ax1.set_title("Training vs Validation Accuracy", fontsize=13, fontweight='bold', pad=10)
    ax1.set_xlabel("Number of Training Samples", fontsize=11)
    ax1.set_ylabel("Accuracy Score", fontsize=11)
    ax1.set_ylim(0.85, 1.01)
    ax1.legend(loc="lower right", frameon=True, facecolor='white', framealpha=0.9)
    ax1.grid(True, linestyle="--", alpha=0.6)

    # Annotate final accuracy
    ax1.annotate(f"Val Acc: {val_mean[-1]*100:.2f}%", 
                 xy=(train_sizes_abs[-1], val_mean[-1]), 
                 xytext=(train_sizes_abs[-1]*0.75, val_mean[-1]-0.025),
                 arrowprops=dict(facecolor='#ff7f0e', shrink=0.05, width=1, headwidth=6),
                 fontsize=10, fontweight='bold', color='#333333')

    # --- Subplot 2: Loss Curve ---
    ax2.plot(train_sizes_abs, train_loss_mean, 'o--', color='#2ca02c', linewidth=2, label='Training Error (Loss)')
    ax2.fill_between(train_sizes_abs, train_loss_mean - train_std, train_loss_mean + train_std, alpha=0.15, color='#2ca02c')

    ax2.plot(train_sizes_abs, val_loss_mean, 'o--', color='#d62728', linewidth=2, label='Validation Error (Loss)')
    ax2.fill_between(train_sizes_abs, val_loss_mean - val_std, val_loss_mean + val_std, alpha=0.15, color='#d62728')

    ax2.set_title("Training vs Validation Error Rate", fontsize=13, fontweight='bold', pad=10)
    ax2.set_xlabel("Number of Training Samples", fontsize=11)
    ax2.set_ylabel("Error Rate (1 - Accuracy)", fontsize=11)
    ax2.set_ylim(-0.005, 0.15)
    ax2.legend(loc="upper right", frameon=True, facecolor='white', framealpha=0.9)
    ax2.grid(True, linestyle="--", alpha=0.6)

    plt.suptitle(f"SecurePass Linear SVM Learning Curves (N = {len(data):,} URLs, 5-Fold CV)", fontsize=14, fontweight='bold', y=1.02)
    plt.tight_layout()

    plt.savefig(args.output_image, bbox_inches='tight')
    plt.close()

    print(f"-> Plot successfully generated and saved to '{args.output_image}'!")
    print("\n" + "=" * 60)
    print(f" Final Training Accuracy:   {train_mean[-1]*100:.2f}%")
    print(f" Final Validation Accuracy: {val_mean[-1]*100:.2f}%")
    print(f" Final Generalization Gap:  {(train_mean[-1] - val_mean[-1])*100:.2f}%")
    print("=" * 60)

if __name__ == "__main__":
    main()
