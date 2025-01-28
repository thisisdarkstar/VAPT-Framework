import { useState } from "react";
import PropTypes from "prop-types";

const Sidebar = ({ isSidebarOpen, selectedBug, setSelectedBug, vulns }) => {
  const [checkedBugs, setCheckedBugs] = useState({}); // Track checkbox state per bug

  const handleBugClick = (bug) => {
    // Set the selected bug when clicked, without affecting the checkbox state
    setSelectedBug(bug);
  };

  const handleCheckboxChange = (bugId) => {
    // Toggle the checkbox state for the clicked bug
    setCheckedBugs((prevChecked) => ({
      ...prevChecked,
      [bugId]: !prevChecked[bugId], // Flip the current state of the checkbox
    }));
  };

  return (
    <div className="flex h-screen w-fit">
      {/* Sidebar */}
      <div
        className={`w-82 bg-gray-800 text-white pt-6 p-4 transition-transform duration-300 ease-in-out fixed left-0 top-0 h-full transform ${
          isSidebarOpen ? "translate-x-0" : "-translate-x-full"
        } custom-scrollbar overflow-y-auto`}
      >
        <h2 className="text-white mb-4 font-bold text-2xl">Vulnerabilities</h2>
        <ul className="space-y-2">
          {vulns.map((bug) => (
            <li
              key={bug.id}
              onClick={() => handleBugClick(bug)} // Only updates the selected bug on click
              className={`cursor-pointer p-2 rounded flex items-center space-x-2 ${
                selectedBug?.id === bug.id ? "bg-blue-600" : "bg-gray-700"
              }`}
            >
              {/* Checkbox */}
              <input
                type="checkbox"
                checked={!!checkedBugs[bug.id]} // Set the checkbox to checked based on the state
                onChange={() => handleCheckboxChange(bug.id)} // Toggle checkbox state when clicked
                className="w-4 h-4"
              />
              <label
                htmlFor={`bug-${bug.id}`}
                className={`cursor-pointer flex-1 truncate ${
                  checkedBugs[bug.id] ? "line-through" : ""
                }`}
              >
                {bug.title}
              </label>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
};
Sidebar.propTypes = {
  isSidebarOpen: PropTypes.bool.isRequired,
  selectedBug: PropTypes.object,
  setSelectedBug: PropTypes.func.isRequired,
  vulns: PropTypes.array.isRequired,
};

export default Sidebar;
