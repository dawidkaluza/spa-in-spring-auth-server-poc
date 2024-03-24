import React, {useState} from "react";
import {useSearchParams} from "react-router-dom";
import axios from "axios";

const Consent = () => {
  const [searchParams] = useSearchParams();

  const scope = searchParams.get("scope");
  const scopes = scope ? scope.split(" ") : [];
  const [checkedScopes, setCheckedScopes] = useState(new Set(scopes));

  const [loading, setLoading] = useState(false);
  const [success, setSuccess] = useState(false);
  const [error, setError] = useState(false);

  const handleScopeChange = (event) => {
    const target = event.target;
    const newCheckedScopes = new Set(checkedScopes);
    if (target.checked) {
      newCheckedScopes.add(target.value);
    } else {
      newCheckedScopes.delete(target.value);
    }

    setCheckedScopes(newCheckedScopes);
  };

  const clientId = searchParams.get("client_id");
  const state = searchParams.get("state");

  const handleSubmit = (event) => {
    event.preventDefault();

    setLoading(true);
    setSuccess(false);
    setError(false);

    const requestData = new URLSearchParams();
    requestData.append("client_id", clientId);
    requestData.append("state", state);
    checkedScopes.forEach(scope => requestData.append("scope", scope));

    axios
      .post(
        "http://localhost:8080/oauth2/authorize",
        requestData,
        {
          withCredentials: true,
          headers: {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
          }
        }
      )
      .then(response => {
        if (response.status === 200) {
          const redirectUrl = response.data?.redirectUrl;
          if (redirectUrl) {
            setSuccess(true);
            setTimeout(() => window.location.assign(redirectUrl), 1500);
            return;
          }
        }

        setError(true);
      })
      .catch(() => {
        setError(true);
      })
      .finally(() => {
        setLoading(false);
      });
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
      <h1
        style={{
          marginTop: "0.5em",
          marginBottom: "0.5em",
        }}
      >
        Consent access
      </h1>

      <div style={{ textAlign: "center" }}>
        <p style={{ margin: 0 }}>
          {clientId} wants to get access to your account.
        </p>
        <p style={{ margin: 0 }}>
          Decide whether you want to grant the access or not.
        </p>
      </div>

      <div style={{ margin: "0.4em 0"}}>
        {scopes.map(scope => (
          <div key={scope}>
            <input
              type={"checkbox"}
              name={"scope"}
              id={"scope_" + scope}
              value={scope}
              checked={checkedScopes.has(scope)}
              onChange={handleScopeChange}
            />

            <label htmlFor={"scope_" + scope}>
              {scope}
            </label>
          </div>
        ))}
      </div>

      <div>
        <input type={"submit"} value={"Approve"}/>
        <input type={"button"} value={"Decline"}/>
      </div>

      {loading &&
        <p>loading...</p>
      }

      {error &&
        <p style={{color: "red"}}>Unexpected error.</p>
      }

      {success &&
        <p style={{color: "green"}}>Consent approved successfully. You will be redirected in a second...</p>
      }
    </form>
  );
};

export {Consent};