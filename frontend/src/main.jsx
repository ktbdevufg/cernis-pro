// Einstiegspunkt (CERNIS PRO 2.0)
// Lädt Token-System + globale Styles, initialisiert i18n, rendert <App/>.

import React from "react";
import ReactDOM from "react-dom/client";

import App from "./App.jsx";
import "./i18n/index.js";
import "./styles/tokens.css";
import "./styles/global.css";

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <App />
  </React.StrictMode>
);
