// utils/nullUndefinedCheck.js

/**
 * Checks whether a given value is null or undefined.
 * @param {*} value - The value to check.
 * @returns {boolean} - Returns true if the value is null or undefined; otherwise false.
 */
function isNullOrUndefined(value) {
  return value === null || value === undefined;
}

module.exports = isNullOrUndefined;