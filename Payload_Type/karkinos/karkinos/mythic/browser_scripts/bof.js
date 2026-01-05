function(task, responses) {
  // Combine all responses into a single string
  const combined = responses.reduce((prev, cur) => {
    return prev + cur;
  }, "");

  if (task.status.includes("error")) {
    return {
      'plaintext': combined,
      'copyable': false
    };
  }

  if (task.completed) {
    // BOF execution completed - display output
    if (responses.length > 0) {
      return {
        'plaintext': combined,
        'copyable': true
      };
    } else {
      return {
        'plaintext': "BOF executed successfully (no output)",
        'copyable': false
      };
    }
  }

  // In-progress status - show intermediate output
  if (combined.length > 0) {
    return {
      'plaintext': combined
    };
  }

  return {
    'plaintext': "Executing BOF..."
  };
}
