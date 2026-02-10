const BASE_URL = "http://127.0.0.1:8000";

export const scanFolder = async (path) => {
  const res = await fetch(`${BASE_URL}/scan?path=${path}`, {
    method: "POST",
  });
  return res.json();
};

export const getResults = async () => {
  const res = await fetch(`${BASE_URL}/results`);
  return res.json();
};
