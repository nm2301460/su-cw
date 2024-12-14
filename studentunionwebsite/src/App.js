import logo from './logo.svg';
import './App.css';
import Home from './my component/Home.js';
import LoginForms from './my component/LoginForms.js';
import RegistrationForm from './my component/Registerationform.js';


function App() {
  return (
    <div className="App">
     <h1>TKH Student Union</h1>
     <LoginForms/>
     <RegistrationForm/>
    </div>
  );
}

export default App;
