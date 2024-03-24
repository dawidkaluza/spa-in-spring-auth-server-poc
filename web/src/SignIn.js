import React, {useState} from "react";
import axios from "axios";
import {useNavigate} from "react-router-dom";

const REQUEST_STATUS = {
  IDLE: "IDLE",
  LOADING: "LOADING",
  USER_ERROR: "USER_ERROR",
  APP_ERROR: "APP_ERROR",
  SUCCESS: "SUCCESS",
};

const SignIn = () => {
  const [fields, setFields] = useState({ username: "", password: "" });
  const [requestStatus, setRequestStatus] = useState(REQUEST_STATUS.IDLE);
  const navigate = useNavigate();

  const handleFieldChange = (event) => {
    const target = event.target;
    setFields({ ...fields, [target.name]: target.value});
  };

  const handleRedirect = (redirectUrl) => {
    switch (redirectUrl.host) {
      case window.location.host: {
        setRequestStatus(REQUEST_STATUS.SUCCESS);
        setTimeout(() => navigate(redirectUrl.pathname + redirectUrl.search), 1500);
        return;
      }

      case "localhost:8080": {
        axios
          .get(
            redirectUrl.href,
            {
              withCredentials: true,
              headers: {
                "Content-Type": "application/json",
                "Accept": "application/json"
              }
            }
          )
          .then(response => {
            if (response.status === 200) {
              const redirectUrl = response.data?.redirectUrl;
              if (redirectUrl) {
                handleRedirect(new URL(redirectUrl));
                return;
              }
            }

            setRequestStatus(REQUEST_STATUS.APP_ERROR);
          })
          .catch(() => {
            setRequestStatus(REQUEST_STATUS.APP_ERROR);
          });

        return;
      }

      default: {
        setRequestStatus(REQUEST_STATUS.SUCCESS);
        setTimeout(() => window.location.assign(redirectUrl), 1500);
      }
    }
  };

  const handleSubmit = (event) => {
    event.preventDefault();
    setRequestStatus(REQUEST_STATUS.LOADING);

    const requestData = new URLSearchParams();
    requestData.append("username", fields.username);
    requestData.append("password", fields.password);

    axios
      .post(
        "http://localhost:8080/sign-in",
        requestData,
        {
          withCredentials: true,
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json"
          }
        }
      )
      .then(response => {
        if (response.status === 200) {
          const redirectUrl = response.data?.redirectUrl;
          if (redirectUrl) {
            handleRedirect(new URL(redirectUrl));
            return;
          }
        }

        setRequestStatus(REQUEST_STATUS.APP_ERROR);
      })
      .catch(error => {
        if (error.response) {
          const response = error.response;

          switch (response.status) {
            case 401:
            case 403: {
              setRequestStatus(REQUEST_STATUS.USER_ERROR);
              return;
            }
          }
        }

        setRequestStatus(REQUEST_STATUS.APP_ERROR);
      });
  };

  const buildRequestStatusMessage = () => {
    switch (requestStatus) {
      case REQUEST_STATUS.LOADING: {
        return (
          <p>loading...</p>
        );
      }

      case REQUEST_STATUS.USER_ERROR: {
        return (
          <p style={{ color: "red" }}>Invalid username or password.</p>
        );
      }

      case REQUEST_STATUS.APP_ERROR: {
        return (
          <p style={{ color: "red" }}>Unexpected error.</p>
        );
      }

      case REQUEST_STATUS.SUCCESS: {
        return (
          <p style={{ color: "green" }}>Signed in successfully. You will be redirected in a second...</p>
        );
      }

      default: {
        return "";
      }
    }
  };

  return (
    <form
      onSubmit={handleSubmit}
      style={{
        marginTop: "5em",
        display: "flex",
        flexDirection: "column",
        alignItems: "center",
        justifyContent: "center",
      }}
    >
      <h1>Sign in</h1>

      <Input
        label={"Username"}
        name={"username"}
        value={fields.username}
        onChange={handleFieldChange}
      />
      <Input
        label={"Password"}
        name={"password"}
        type={"password"}
        value={fields.password}
        onChange={handleFieldChange}
      />

      <input type={"submit"} value={"Submit"} />

      {buildRequestStatusMessage()}
    </form>
  )
};

const Input = ({ label, name, type = "text", value, onChange}) => {
  return (
    <div>
      <span>{label}: </span>
      <input
        type={type}
        name={name}
        value={value}
        onChange={onChange}
      />
    </div>
  );
};

export {SignIn};