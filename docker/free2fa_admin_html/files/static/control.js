// control.js
// Copyright (C) 2024 Voloskov Aleksandr Nikolaevich

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

const API_BASE_URL = window.location.origin;

document
  .getElementById("logoutButton")
  .addEventListener("click", function () {
    // Deleting a token from sessionStorage
    sessionStorage.removeItem("token");

    // Switching the display of sections
    document.getElementById("loginSection").style.display = "block";
    document.getElementById("mainContent").style.display = "none";
    document.getElementById("changePasswordSection").style.display =
      "none";
  });

function validateUsernameFormat(username) {
  const regex = /^[^\s\\]+\\[^\s\\]+$/;
  return regex.test(username);
}

function showNotification(message, type = "success") {
  const notification = document.getElementById("notification");
  notification.textContent = message;
  notification.style.display = "block";

  // Delete previous classes, if any
  notification.classList.remove(
    "notification-success",
    "notification-error",
  );

  // Add the appropriate class depending on the type of notification
  if (type === "success") {
    notification.classList.add("notification-success");
  } else {
    notification.classList.add("notification-error");
  }

  setTimeout(() => {
    notification.style.display = "none";
  }, 3000);
}

document
  .getElementById("changePasswordForm")
  .addEventListener("submit", function (e) {
    e.preventDefault();

    const oldPassword = document.getElementById(
      "changePasswordOldPassword",
    ).value;
    const newPassword = document.getElementById("newPassword").value;
    const confirmNewPassword =
      document.getElementById("confirmNewPassword").value;

    // Password match check
    if (newPassword !== confirmNewPassword) {
      // If the passwords do not match, we show an error message
      document.getElementById("passwordMismatch").style.display = "block";
      return;
    } else {
      document.getElementById("passwordMismatch").style.display = "none";
    }

    changePassword(oldPassword, newPassword);
  });

document
  .getElementById("changePasswordButton")
  .addEventListener("click", function () {
    document.getElementById("changePasswordSection").style.display =
      "block";
  });

async function changePassword(oldPassword, newPassword) {
  const token = sessionStorage.getItem("token");
  try {
    const response = await fetch(`${API_BASE_URL}/api/change-password`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        old_password: oldPassword,
        new_password: newPassword,
      }),
    });

    if (!response.ok) {
      throw new Error(
        `Failed to change password: ${response.statusText}`,
      );
    }

    showNotification("Password changed successfully", "success");
    document.getElementById("changePasswordSection").style.display =
      "none";
    location.reload();
  } catch (error) {
    console.error("Error changing password:", error);
    showNotification("Failed to change password", "error");
  }
}

document
  .getElementById("addUserForm")
  .addEventListener("submit", async function (e) {
    e.preventDefault();
    const username = document.getElementById("username").value;
    if (!validateUsernameFormat(username)) {
      alert("Username must be in the format domain\\user.");
      return;
    }
    const telegramId = document.getElementById("telegramId").value;
    const isBypass = document.getElementById("isBypass").checked;
    // Changing the way the value for OTP is obtained
    const otpEnabled = document.getElementById("otpEnabled").checked ? "1" : "0";

    const user = {
      domain_and_username: username,
      telegram_id: telegramId,
      is_bypass: isBypass,
      otp: otpEnabled,
    };

    try {
      const response = await fetch(`${API_BASE_URL}/api/users/`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${sessionStorage.getItem("token")}`,
        },
        body: JSON.stringify(user),
      });

      const data = await response.json();
      if (response.ok) {
        showNotification(data.message, "success");
      } else {
        showNotification(data.message, "error");
      }
    } catch (error) {
      console.error("Error adding user:", error);
      showNotification("Failed to add user", "error");
    } finally {
      document.getElementById("addUserForm").reset();
      loadUsers();
    }
  });

document.getElementById("loadUsers").addEventListener("click", loadUsers);

// Function for creating an edit button
function createEditButton(user) {
  const button = document.createElement('button');
  button.textContent = 'Edit';
  button.addEventListener('click', function () {
    showEditForm([user.domain_and_username, user.telegram_id, user.is_bypass, user.otp]);
  });
  return button;
}

// Function for creating a delete button
function createDeleteButton(username) {
  const button = document.createElement('button');
  button.textContent = 'Delete';
  button.addEventListener('click', function () {
    deleteUser(username);
  });
  return button;
}


async function loadUsers() {
  const token = sessionStorage.getItem("token");
  try {
    const response = await fetch(`${API_BASE_URL}/api/users/`, {
      method: "GET",
      headers: {
        Authorization: `Bearer ${token}`,
        "Content-Type": "application/json",
      },
    });

    if (!response.ok) {
      throw new Error(`Error fetching users: ${response.statusText}`);
    }

    const users = await response.json();
    const usersTableBody = document.querySelector("#usersTable tbody");
    usersTableBody.innerHTML = "";

    users.forEach((user) => {
      const tr = document.createElement('tr');

      // Создание и заполнение ячеек для каждого поля пользователя
      const domainAndUsernameCell = document.createElement('td');
      domainAndUsernameCell.textContent = user.domain_and_username;
      tr.appendChild(domainAndUsernameCell);

      const telegramIdCell = document.createElement('td');
      telegramIdCell.textContent = user.telegram_id;
      tr.appendChild(telegramIdCell);

      const isBypassCell = document.createElement('td');
      isBypassCell.textContent = user.is_bypass ? "Yes" : "No";
      tr.appendChild(isBypassCell);

      const otpCell = document.createElement('td');
      otpCell.textContent = user.otp;
      tr.appendChild(otpCell);

      // Создание и добавление кнопок к каждой строке
      const actionsCell = document.createElement('td');
      const editButton = createEditButton(user);
      const deleteButton = createDeleteButton(user.domain_and_username);
      actionsCell.appendChild(editButton);
      actionsCell.appendChild(deleteButton);
      tr.appendChild(actionsCell);

      usersTableBody.appendChild(tr);
    });
  } catch (error) {
    console.error("Error loading users:", error);
    showNotification(error.message, "error");
  }
}


async function deleteUser(username) {
  const token = sessionStorage.getItem("token");
  try {
    const fixedUsername = encodeURIComponent(username);
    const response = await fetch(
      `${API_BASE_URL}/api/users/${fixedUsername}`,
      {
        method: "DELETE",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      },
    );

    if (!response.ok) {
      throw new Error(`Error deleting user: ${response.statusText}`);
    }

    showNotification("User deleted successfully", "success");
    loadUsers();
  } catch (error) {
    console.error("Error deleting user:", error);
    showNotification("Error deleting user", "error");
  }
}

function showEditForm(user) {
  const otpStatus = user[3];
  const otpCheckbox = document.getElementById("editOtpEnabled");
  const otpLabel = document.querySelector("label[for='editOtpEnabled']");
  document.getElementById("editUserSection").style.display = "block";
  document.getElementById("originalUsername").value = user[0];
  document.getElementById("editUsernameOriginal").value = user[0];
  document.getElementById("editUsername").value = user[0];
  document.getElementById("editTelegramId").value = user[1];
  document.getElementById("editisBypass").checked = user[2];
  if (otpStatus === "Configured") {
    otpCheckbox.checked = false; // Reset checkbox status
    otpLabel.textContent = "Reset OTP"; // Change of signature
  } else {
    otpCheckbox.checked = otpStatus === "Enabled";
    otpLabel.textContent = "Enable OTP"; // Revert back if not "Configured".
  }
}

document
  .getElementById("editUserForm")
  .addEventListener("submit", async function (e) {
    e.preventDefault();
    const originalUsername = encodeURIComponent(document.getElementById("originalUsername").value);
    const newUsername = document.getElementById("editUsername").value;
    if (!validateUsernameFormat(newUsername)) {
      alert("Username must be in the format domain\\user.");
      return;
    }
    const newTelegramId = document.getElementById("editTelegramId").value;
    const newIsBypass = document.getElementById("editisBypass").checked;

    // Get the current state of the OTP checkbox
    const otpCheckboxChecked = document.getElementById("editOtpEnabled").checked;
    // Determine the OTP value based on the checkbox state and signature
    let otpValue;
    const otpLabel = document.querySelector("label[for='editOtpEnabled']").textContent;
    if (otpLabel === "Reset OTP" && otpCheckboxChecked) {
      otpValue = "1"; // Value for OTP reset
    } else if (otpLabel === "Enable OTP") {
      otpValue = otpCheckboxChecked ? "1" : "0"; // Turning OTP on or off
    }

    const requestBody = {
      domain_and_username: newUsername,
      telegram_id: newTelegramId,
      is_bypass: newIsBypass,
      otp: otpValue, // Only if otpValue is defined
    };

    // Remove the otp property from the object if its value is not defined
    if (otpValue === undefined) {
      delete requestBody.otp;
    }

    console.log("Sending PUT request with data:", JSON.stringify(requestBody));

    try {
      const token = sessionStorage.getItem("token");
      const response = await fetch(`${API_BASE_URL}/api/users/${originalUsername}`, {
        method: "PUT",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify(requestBody),
      });

      const data = await response.json();
      if (response.ok) {
        showNotification(data.message, "success");
      } else {
        showNotification(data.message, "error");
      }
    } catch (error) {
      console.error("Error updating user:", error);
      showNotification("Failed to update user", "error");
    } finally {
      document.getElementById("editUserForm").reset();
      loadUsers();
    }
  });

// Adding a handler for user search form
document
  .getElementById("searchUserForm")
  .addEventListener("submit", async function (e) {
    e.preventDefault();
    const searchUsername = encodeURIComponent(
      document.getElementById("searchUsername").value,
    );
    const token = sessionStorage.getItem("token");
    try {
      const response = await fetch(
        `${API_BASE_URL}/api/users/${searchUsername}`,
        {
          headers: {
            Authorization: `Bearer ${token}`,
          },
        },
      );

      if (!response.ok) {
        throw new Error("User not found or server error");
      }

      const user = await response.json();

      if (user) {
        const usersList = document.getElementById("usersList");
        usersList.innerHTML = "";

        const li = document.createElement("li");
        li.textContent = `${user.domain_and_username}, Telegram ID: ${user.telegram_id}, Bypass user: ${user.is_bypass}`;

        const deleteButton = document.createElement("button");
        deleteButton.textContent = "Delete";
        deleteButton.onclick = function () {
          deleteUser(user.domain_and_username)
            .then(() => {
              loadUsers();
            })
            .catch((error) => {
              console.error("Error deleting user:", error);
              showNotification("Error deleting user", "error");
            });
        };

        const editButton = document.createElement("button");
        editButton.textContent = "Edit";
        editButton.onclick = function () {
          showEditForm([
            user.domain_and_username,
            user.telegram_id,
            user.is_bypass,
          ]);
        };

        li.appendChild(editButton);
        li.appendChild(deleteButton);
        usersList.appendChild(li);
      }
    } catch (error) {
      showNotification(error.message, "error");
    }
  });

document
  .getElementById("loginForm")
  .addEventListener("submit", async function (e) {
    e.preventDefault();
    const username = document.getElementById("loginUsername").value;
    const password = document.getElementById("loginPassword").value;

    // Sending a request to the server for authentication
    const response = await fetch(`${API_BASE_URL}/api/auth/admin`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        username: username,
        password: password,
      }),
    });

    if (response.ok) {
      const data = await response.json();
      sessionStorage.setItem("token", data.access_token);
      if (username === "admin" && password === "admin") {
        document.getElementById("changePasswordSection").style.display =
          "block";
      } else {
        document.getElementById("mainContent").style.display = "block";
      }
      document.getElementById("loginSection").style.display = "none";
      document.getElementById("logoutButton").style.display = "block";
    } else {
      showNotification("Login failed!", "error");
    }
  });

document.addEventListener("DOMContentLoaded", async function () {
  checkAuthentication();
  checkResetPasswordEnabled();
  setupResetPasswordButton();
});

async function checkResetPasswordEnabled() {
  try {
    const response = await fetch(
      `${API_BASE_URL}/api/reset-password-enabled`,
    );
    const data = await response.json();

    if (data.resetPasswordEnabled) {
      document.getElementById("resetPasswordButtonDiv").style.display =
        "block";
    }
  } catch (error) {
    console.error("Error checking reset password status:", error);
  }
}

function setupResetPasswordButton() {
  const resetPasswordButton = document.getElementById(
    "resetPasswordButton",
  );
  if (resetPasswordButton) {
    resetPasswordButton.addEventListener("click", function () {
      document.getElementById("resetPasswordSection").style.display =
        "block";
    });
  }
}

async function checkAuthentication() {
  const token = sessionStorage.getItem("token");
  if (token) {
    try {
      const response = await fetch(`${API_BASE_URL}/api/verify-token`, {
        method: "GET",
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });

      if (!response.ok) {
        throw new Error("Token verification failed");
      }

      document.getElementById("loginSection").style.display = "none";
      document.getElementById("mainContent").style.display = "block";
      document.getElementById("logoutButton").style.display = "block";
    } catch (error) {
      console.error("Error verifying token:", error);
      sessionStorage.removeItem("token");
      redirectToLogin();
    }
  } else {
    redirectToLogin();
  }
}

function redirectToLogin() {
  document.getElementById("loginSection").style.display = "block";
  document.getElementById("mainContent").style.display = "none";
  document.getElementById("logoutButton").style.display = "none";
}

document
  .getElementById("resetPasswordForm")
  .addEventListener("submit", async function (e) {
    e.preventDefault();
    const encryptionKey = document.getElementById("encryptionKey").value;

    try {
      const response = await fetch(`${API_BASE_URL}/api/reset-password`, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({ secret_key: encryptionKey }),
      });

      const data = await response.json();
      if (response.ok) {
        showNotification(data.message, "success");
      } else {
        showNotification(data.message, "error");
      }
    } catch (error) {
      console.error("Error resetting password:", error);
      showNotification("Failed to reset password", "error");
    }
  });