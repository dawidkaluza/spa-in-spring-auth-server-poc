import React from "react";
import {createRoot} from "react-dom/client";
import {SignIn} from "./SignIn";
import {createBrowserRouter, Navigate, RouterProvider} from "react-router-dom";
import {Consent} from "./Consent";

const router = createBrowserRouter([
  {
    path: "/",
    element: <Navigate to={"/sign-in"} />
  },
  {
    path: "/sign-in",
    element: <SignIn />
  },
  {
    path: "/consent",
    element: <Consent />
  }
]);

const rootElement = document.getElementById("app");
const root = createRoot(rootElement);
root.render(
  <>
    <RouterProvider router={router} />
  </>
)