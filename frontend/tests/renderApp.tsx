import { render } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";

import { App } from "../src/App";

/** Renders the whole app (real routes and layout) at the given URL. */
export function renderApp(path = "/") {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <App />
    </MemoryRouter>,
  );
}
