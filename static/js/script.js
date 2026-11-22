// Static JavaScript for the Flask web app

document.addEventListener("DOMContentLoaded", function () {
  console.log(
    "TravelExpense Pro with Currency Conversion loaded successfully!"
  );

  // Auto-hide flash messages after 5 seconds
  const alerts = document.querySelectorAll(".alert");
  alerts.forEach((alert) => {
    setTimeout(() => {
      alert.style.opacity = "0";
      setTimeout(() => {
        alert.style.display = "none";
      }, 300);
    }, 5000);
  });

  // Form validation for expense forms
  const expenseForm = document.getElementById("expense-form");
  if (expenseForm) {
    expenseForm.addEventListener("submit", function (e) {
      const amount = document.getElementById("local_amount");
      const destination = document.getElementById("destination");
      const purpose = document.getElementById("purpose");

      if (amount && parseFloat(amount.value) <= 0) {
        e.preventDefault();
        alert("Amount must be greater than 0");
        return false;
      }

      if (destination && destination.value.trim() === "") {
        e.preventDefault();
        alert("Destination is required");
        return false;
      }

      if (purpose && purpose.value.trim() === "") {
        e.preventDefault();
        alert("Purpose is required");
        return false;
      }
    });
  }

  // Modal functionality
  const modal = document.getElementById("expense-modal");
  const openModalBtn = document.getElementById("open-expense-modal");
  const closeModalBtn = document.querySelector(".close");

  if (openModalBtn && modal) {
    openModalBtn.addEventListener("click", function () {
      modal.style.display = "block";
    });
  }

  if (closeModalBtn && modal) {
    closeModalBtn.addEventListener("click", function () {
      modal.style.display = "none";
    });
  }

  // Close modal when clicking outside
  if (modal) {
    window.addEventListener("click", function (event) {
      if (event.target === modal) {
        modal.style.display = "none";
      }
    });
  }

  // Table sorting functionality
  const tables = document.querySelectorAll(".table");
  tables.forEach((table) => {
    const headers = table.querySelectorAll("th");
    headers.forEach((header, index) => {
      if (header.textContent.trim() !== "Actions") {
        header.style.cursor = "pointer";
        header.addEventListener("click", () => sortTable(table, index));
      }
    });
  });
});

// Sort table function
function sortTable(table, columnIndex) {
  const tbody = table.querySelector("tbody");
  const rows = Array.from(tbody.querySelectorAll("tr"));

  const sorted = rows.sort((a, b) => {
    const aText = a.cells[columnIndex].textContent.trim();
    const bText = b.cells[columnIndex].textContent.trim();

    // Try to parse as numbers first
    const aNum = parseFloat(aText);
    const bNum = parseFloat(bText);

    if (!isNaN(aNum) && !isNaN(bNum)) {
      return aNum - bNum;
    }

    return aText.localeCompare(bText);
  });

  // Clear tbody and append sorted rows
  tbody.innerHTML = "";
  sorted.forEach((row) => tbody.appendChild(row));
}

// Currency formatter
function formatCurrency(amount, currency = "USD") {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: currency,
  }).format(amount);
}

// Currency conversion functionality
function convertAmount(amount, fromCurrency, exchangeRates) {
  if (fromCurrency === "USD") {
    return amount;
  }

  if (exchangeRates && exchangeRates[fromCurrency]) {
    return amount / exchangeRates[fromCurrency];
  }

  return amount; // Fallback to original amount
}

// Real-time USD conversion display
function updateUSDDisplay() {
  const amountInput = document.getElementById("local_amount");
  const currencySelect = document.getElementById("local_currency");
  const usdDisplay = document.getElementById("usd-display");

  if (amountInput && currencySelect && usdDisplay) {
    const amount = parseFloat(amountInput.value) || 0;
    const currency = currencySelect.value;

    if (amount > 0 && currency !== "USD") {
      // This would require real-time exchange rate API call
      // For demo purposes, showing placeholder
      usdDisplay.textContent = `≈ $${(amount * 0.75).toFixed(
        2
      )} USD (estimated)`;
      usdDisplay.style.display = "block";
    } else if (currency === "USD") {
      usdDisplay.textContent = `$${amount.toFixed(2)} USD`;
      usdDisplay.style.display = "block";
    } else {
      usdDisplay.style.display = "none";
    }
  }
}

// Event listeners for real-time conversion
document.addEventListener("DOMContentLoaded", function () {
  const amountInput = document.getElementById("local_amount");
  const currencySelect = document.getElementById("local_currency");

  if (amountInput && currencySelect) {
    amountInput.addEventListener("input", updateUSDDisplay);
    currencySelect.addEventListener("change", updateUSDDisplay);
  }
});

document.querySelectorAll(".view-details").forEach((btn) => {
  btn.addEventListener("click", () => {
    viewEmployeeDetails(
      btn.dataset.id,
      btn.dataset.first,
      btn.dataset.email,
      btn.dataset.phone
    );
  });
});

function showDeclineReason(reason) {
  alert(reason);
}

function showReport(button) {
  const title = button.dataset.title;
  console.log(title);
}
document.querySelectorAll(".view-details").forEach((button) => {
  button.addEventListener("click", function () {
    const id = this.dataset.id;
    const username = this.dataset.username;
    const email = this.dataset.email;
    const role = this.dataset.role;
    viewEmployeeDetails(id, username, email, role);
  });
});
