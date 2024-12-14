import React from 'react';
const RegistrationForm = () => {
  let name = '';
  let email = '';
  let password = '';
  let isAdmin = false;
  let message = '';
  const registerUser = () => {
    fetch('http://localhost:3000/user/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name, email, password, isAdmin }),
    })
      .then((response) => {
        if (!response.ok) {
          throw new Error('Registration failed');
        }
        message = 'Registration successful';
        alert(message); 
      })
      .catch((error) => {
        message = error.message;
        alert(message); 
      });
  };
  return (
    <div className="form-section">
      <h3>User Registration</h3>
      <form>
        <input
          type="text"
          placeholder="Name"
          onChange={(e) => (name = e.target.value)} 
          required
        />
        <br />
        <input
          type="email"
          placeholder="Email"
          onChange={(e) => (email = e.target.value)} 
          required
        />
        <br />
        <input
          type="password"
          placeholder="Password"
          onChange={(e) => (password = e.target.value)} 
          required
        />
        <br />
        <label>
          <input
            type="checkbox"
            checked={isAdmin}
            onChange={(e) => (isAdmin = e.target.checked)} 
          />
          Admin
        </label>
        <br />
        <button type="button" onClick={registerUser}>
          Register
        </button>
      </form>
      <p>{message}</p> 
    </div>
  );
};

export default RegistrationForm;
