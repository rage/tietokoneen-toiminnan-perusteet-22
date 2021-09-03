import axios from "axios"
import { accessToken } from "./moocfi"

export async function fetchQuizzesProgress() {
  const response = await axios.get(
    "https://quizzes.mooc.fi/api/v2/general/course/19f6f5f5-59a8-4859-a9b4-b2bf3e49c04b/progress",
    { headers: { Authorization: `Bearer ${accessToken()}` } },
  )
  return response.data
}

export async function fetchQuizNames() {
  const response = await axios.get(
    "https://quizzes.mooc.fi/api/v1/quizzes/19f6f5f5-59a8-4859-a9b4-b2bf3e49c04b/titles/fi_FI",
  )
  return response.data
}
