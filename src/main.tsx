import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { App } from "./App";
import { insideTauri } from "./api/backend";
import { ConfirmProvider } from "./components/ConfirmDialog";
import { ToastProvider } from "./components/Toasts";
import "./styles/index.css";

const root = document.getElementById("root");
if (!root) throw new Error("В index.html нет #root.");

createRoot(root).render(
  <StrictMode>
    <ToastProvider>
      <ConfirmProvider>
        <App />
      </ConfirmProvider>
    </ToastProvider>
  </StrictMode>,
);

// Scenario switcher for the browser mock. The condition is a build-time literal, so production drops it.
if (import.meta.env.DEV && !insideTauri) {
  void import("./dev/DevSwitcher").then(({ DevSwitcher }) => {
    const host = document.createElement("div");
    host.id = "dev-switcher";
    document.body.append(host);
    createRoot(host).render(<DevSwitcher />);
  });
}
