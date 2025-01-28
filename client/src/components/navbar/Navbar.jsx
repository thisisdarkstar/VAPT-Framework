import React, { useState } from 'react';

function Navbar() {
    const [isModalOpen, setIsModalOpen] = useState(false);
    const [domain, setDomain] = useState("");

    const handleAddDomain = ({ isSidebarOpen }) => {
        e.preventDefault();
        console.log("Added Domain: ", domain);
        setDomain("");  // Clear the input after submission
        setIsModalOpen(false);  // Close the modal
    };

    return (
        <div>
            {/* Navbar */}
            <nav className="bg-gray-800 p-4 z-20">
                <div className="max-w-7xl mx-auto flex justify-between items-center">
                    <div className="text-white font-bold text-2xl">VAPT Framework</div>
                    <div>
                        <button
                            onClick={() => setIsModalOpen(true)}
                            className="text-white bg-blue-500 px-4 py-2 cursor-pointer rounded hover:bg-blue-600"
                        >
                            Add Domain
                        </button>
                    </div>
                </div>
            </nav>

            {/* Modal for adding domain */}
            {isModalOpen && (
                <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
                    <div className="bg-white p-6 rounded-lg shadow-lg w-96">
                        <h2 className="text-xl font-semibold mb-4">Add Target Domain</h2>
                        <form onSubmit={handleAddDomain}>
                            <div className="mb-4">
                                <label htmlFor="domain" className="block text-sm font-medium text-gray-700">Domain URL</label>
                                <input
                                    type="url"
                                    id="domain"
                                    value={domain}
                                    onChange={(e) => setDomain(e.target.value)}
                                    required
                                    className="mt-1 p-2 border border-gray-300 rounded-md w-full"
                                    placeholder="Enter target URL"
                                />
                            </div>
                            <div className="flex justify-between">
                                <button
                                    type="button"
                                    onClick={() => setIsModalOpen(false)}
                                    className="text-gray-600 cursor-pointer hover:text-gray-900"
                                >
                                    Cancel
                                </button>
                                <button
                                    type="submit"
                                    className="text-white bg-blue-500 px-4 py-2 rounded cursor-pointer hover:bg-blue-600"
                                >
                                    Add Domain
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            )}
        </div>
    );
}

export default Navbar;
