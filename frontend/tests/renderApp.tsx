import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { App } from "../src/App";
import { AuthProvider } from "../src/auth/AuthContext";

/** Renders the whole app (real routes, auth and layout) at the given URL. */
export function renderApp(path = "/") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <AuthProvider>
        <App />
      </AuthProvider>
    </MemoryRouter>,
  );
}
