import React, { useState } from 'react';
import './App.css';
import Sidebar from './components/sidebar/Sidebar';
import Navbar from './components/navbar/Navbar';

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
      />

      {/* Main content area */}
      <div
        className={`transition-all duration-300 ease-in-out ${isSidebarOpen ? 'ml-80 w-[calc(100vw-20rem)]' : 'ml-0 w-full'}`}
      >
        <Navbar />
        <div className="details p-6">
          <button
            onClick={toggleSidebar}
            className="bg-blue-500 text-white p-2 rounded cursor-pointer"
          >
            {isSidebarOpen ? 'Close Sidebar' : 'Open Sidebar'}
          </button>

          <div className="flex-1 py-6">
            {selectedBug ? (
              <>
                <h1 className="text-2xl font-bold">{selectedBug.title}</h1>
                <p className="mt-4">{selectedBug.description}</p>
              </>
            ) : (
              <p>Select a bug to see details</p>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

export default App;
