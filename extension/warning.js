document.addEventListener("DOMContentLoaded", () => {
  const urlParams = new URLSearchParams(window.location.search);
  const targetUrl = urlParams.get("url") || "Unknown Website";

  const targetUrlDisplay = document.getElementById("target-url");
  if (targetUrlDisplay) {
    targetUrlDisplay.textContent = targetUrl;
  }

  const btnSafety = document.getElementById("btn-back-safety");
  if (btnSafety) {
    btnSafety.onclick = () => {
      window.location.href = "http://localhost:5173/vault";
    };
  }

  const btnProceed = document.getElementById("btn-proceed-unsafe");
  if (btnProceed) {
    btnProceed.onclick = () => {
      // Append bypass parameter or redirect directly
      const separator = targetUrl.includes("?") ? "&" : "?";
      window.location.href = targetUrl + separator + "sp_bypass_phishing=true";
    };
  }
});
