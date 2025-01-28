import PropTypes from "prop-types";

const BugContainer = ({ selectedBug }) => {
  return (
    <div className="details p-6">
      <div className="flex-1">
        {selectedBug ? (
          <>
            <h1 className="text-2xl font-bold">{selectedBug.title}</h1>
            <p className="mt-4">
              <strong>Description:</strong> {selectedBug.details.description}
            </p>
            <details className="mt-4 bg-gray-100 p-4 rounded shadow">
              <summary className="cursor-pointer font-semibold">
                More details
              </summary>
              <div className="mt-2">
                <p className="mt-2">
                  <strong>Impact:</strong> {selectedBug.details.impact}
                </p>
                <p className="mt-2">
                  <strong>Recommendations:</strong>{" "}
                  {selectedBug.details.recommendations}
                </p>
                <p className="mt-2">
                  <strong>Reference:</strong>{" "}
                  <a
                    href={selectedBug.details.reference}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="text-blue-500 underline"
                  >
                    {selectedBug.details.reference}
                  </a>
                </p>
                <p className="mt-2">
                  <strong>Severity:</strong> {selectedBug.metadata.severity}
                </p>
                <p className="mt-2">
                  <strong>CVSS Score:</strong> {selectedBug.metadata.cvss_score}
                </p>
                <p className="mt-2">
                  <strong>CWE ID:</strong> {selectedBug.metadata.cwe_id}
                </p>
                <p className="mt-2">
                  <strong>OWASP Category:</strong>{" "}
                  {selectedBug.metadata.owasp_category}
                </p>
              </div>
            </details>
          </>
        ) : (
          <p className="text-xl font-bold">Select a bug to see details</p>
        )}
      </div>
    </div>
  );
};

BugContainer.propTypes = {
  selectedBug: PropTypes.shape({
    title: PropTypes.string,
    details: PropTypes.shape({
      description: PropTypes.string,
      impact: PropTypes.string,
      recommendations: PropTypes.string,
      reference: PropTypes.string,
    }),
    metadata: PropTypes.shape({
      severity: PropTypes.string,
      cvss_score: PropTypes.number,
      cwe_id: PropTypes.string,
      owasp_category: PropTypes.string,
    }),
  }),
};

export default BugContainer;
