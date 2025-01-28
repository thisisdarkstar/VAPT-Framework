import { useState } from "react";
import "./App.css";
import Sidebar from "./components/sidebar/Sidebar";
import Navbar from "./components/navbar/Navbar";
import BugContainer from "./components/bugContainer/BugContainer";
import { sortedVulns } from "./data/vulns";

function App() {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const [selectedBug, setSelectedBug] = useState(null);

  const toggleSidebar = () => {
    setIsSidebarOpen((prevState) => !prevState); // Toggle the sidebar visibility
  };

  return (
    <div className="flex">
      {/* Sidebar */}
      <Sidebar
        isSidebarOpen={isSidebarOpen}
        setIsSidebarOpen={setIsSidebarOpen}
        toggleSidebar={toggleSidebar}
        selectedBug={selectedBug}
        setSelectedBug={setSelectedBug}
        vulns={sortedVulns}
      />

      {/* Main content area */}
      <div
        className={`transition-all duration-300 ease-in-out ${
          isSidebarOpen ? "ml-80 w-[calc(100vw-20rem)]" : "ml-0 w-full"
        }`}
      >
        <Navbar />
        <button
          onClick={toggleSidebar}
          className="bg-blue-500 text-white p-2 rounded cursor-pointer mx-6 mt-2"
        >
          {isSidebarOpen ? "Close Sidebar" : "Open Sidebar"}
        </button>
        <BugContainer
          selectedBug={selectedBug}
          toggleSidebar={toggleSidebar}
          isSidebarOpen={isSidebarOpen}
        />
      </div>
    </div>
  );
}

export default App;
