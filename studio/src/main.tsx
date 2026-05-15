/* @refresh reload */
import { render } from "solid-js/web";
import App from "./App";
import "./styles.css";

const root = document.getElementById("root");
if (!root) {
  throw new Error(
    "Lictor Studio: failed to find #root in index.html — this should be impossible.",
  );
}

render(() => <App />, root);
