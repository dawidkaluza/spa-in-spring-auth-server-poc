import React from "react";

const SignIn = () => {

  const handleFieldChange = (event) => {
    // TODO impl
  };

  const handleSubmit = (event) => {
    event.preventDefault();

    //TODO impl
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
        value={"admin"}
        onChange={handleFieldChange}
      />
      <Input
        label={"Password"}
        name={"password"}
        type={"password"}
        value={"passwd"}
        onChange={handleFieldChange}
      />

      <input type={"submit"} value={"Submit"} />
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