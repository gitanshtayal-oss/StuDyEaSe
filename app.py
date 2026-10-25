"""EduMirror — single-file Flask learning app.

Quick start (from this directory):
  py -m venv .venv
  # Windows: .venv\\Scripts\\activate
  # macOS/Linux: source .venv/bin/activate
  pip install Flask google-genai python-dotenv
  # Set GEMINI_API_KEY in a .env file next to app.py.
  # Optionally set GEMINI_MODEL there too.
  py app.py

The default provider is the Gemini API. No key is required to load the UI, but
AI routes return a clear setup message until one is configured.
"""

from __future__ import annotations

import json
import hmac
import os
import re
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from flask import Flask, Response, jsonify, render_template_string, request, session
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv(Path(__file__).resolve().with_name(".env"))

app = Flask(__name__)
app.config["JSON_SORT_KEYS"] = False
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY")
app.config["SESSION_COOKIE_HTTPONLY"] = True
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"
app.config["SESSION_COOKIE_SECURE"] = os.environ.get("FLASK_COOKIE_SECURE", "").lower() == "true"
DATABASE = os.environ.get("EDUMIRROR_DB", os.path.join(os.path.dirname(__file__), "edumirror.sqlite3"))
MAX_TOPIC_LENGTH = 180
MAX_PASSWORD_LENGTH = 128
_db_ready = False


def connect_db():
	db = sqlite3.connect(DATABASE, timeout=15)
	db.row_factory = sqlite3.Row
	db.execute("PRAGMA foreign_keys = ON")
	return db


def init_db():
	global _db_ready
	with connect_db() as db:
		db.executescript("""
			CREATE TABLE IF NOT EXISTS app_settings (
				key TEXT PRIMARY KEY,
				value TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS users (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				username TEXT NOT NULL,
				username_key TEXT NOT NULL UNIQUE,
				email TEXT NOT NULL,
				email_key TEXT NOT NULL UNIQUE,
				password_hash TEXT NOT NULL,
				created_at TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS learning_history (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
				session_key TEXT NOT NULL DEFAULT '',
				topic TEXT NOT NULL,
				activity TEXT NOT NULL,
				created_at TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS explanation_history (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
				session_key TEXT NOT NULL,
				topic TEXT NOT NULL,
				level TEXT NOT NULL,
				style TEXT NOT NULL,
				result_json TEXT NOT NULL,
				created_at TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS quizzes (
				id TEXT PRIMARY KEY,
				owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
				session_key TEXT NOT NULL DEFAULT '',
				topic TEXT NOT NULL,
				questions TEXT NOT NULL,
				user_answers TEXT NOT NULL DEFAULT '[]',
				completed INTEGER NOT NULL DEFAULT 0,
				created_at TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS quiz_results (
				id INTEGER PRIMARY KEY AUTOINCREMENT,
				owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
				session_key TEXT NOT NULL DEFAULT '',
				quiz_id TEXT NOT NULL,
				topic TEXT NOT NULL,
				score INTEGER NOT NULL,
				total INTEGER NOT NULL,
				created_at TEXT NOT NULL
			);
			CREATE TABLE IF NOT EXISTS revision_cards (
				id TEXT PRIMARY KEY,
				owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
				session_key TEXT NOT NULL,
				quiz_id TEXT NOT NULL,
				topic TEXT NOT NULL,
				question TEXT NOT NULL,
				choices TEXT NOT NULL,
				correct_answer INTEGER NOT NULL,
				user_answer INTEGER NOT NULL,
				explanation TEXT NOT NULL,
				due_at TEXT NOT NULL,
				review_count INTEGER NOT NULL DEFAULT 0,
				mastered INTEGER NOT NULL DEFAULT 0,
				created_at TEXT NOT NULL
			);
		""")
		for table in ("learning_history", "quizzes", "quiz_results"):
			columns = {row["name"] for row in db.execute(f"PRAGMA table_info({table})")}
			if "owner_id" not in columns:
				db.execute(f"ALTER TABLE {table} ADD COLUMN owner_id INTEGER REFERENCES users(id) ON DELETE CASCADE")
			if "session_key" not in columns:
				db.execute(f"ALTER TABLE {table} ADD COLUMN session_key TEXT NOT NULL DEFAULT ''")
		explanation_columns = {row["name"] for row in db.execute("PRAGMA table_info(explanation_history)")}
		if "activity_type" not in explanation_columns:
			db.execute("ALTER TABLE explanation_history ADD COLUMN activity_type TEXT NOT NULL DEFAULT 'explanation'")
		db.executescript("""
			CREATE INDEX IF NOT EXISTS learning_history_owner_idx ON learning_history(owner_id);
			CREATE INDEX IF NOT EXISTS learning_history_session_idx ON learning_history(session_key);
			CREATE INDEX IF NOT EXISTS explanation_history_owner_idx ON explanation_history(owner_id, id);
			CREATE INDEX IF NOT EXISTS explanation_history_session_idx ON explanation_history(session_key, id);
			CREATE INDEX IF NOT EXISTS explanation_history_activity_idx ON explanation_history(owner_id, activity_type, id);
			CREATE INDEX IF NOT EXISTS quizzes_owner_idx ON quizzes(owner_id);
			CREATE INDEX IF NOT EXISTS quizzes_session_idx ON quizzes(session_key);
			CREATE INDEX IF NOT EXISTS quiz_results_owner_idx ON quiz_results(owner_id);
			CREATE INDEX IF NOT EXISTS quiz_results_session_idx ON quiz_results(session_key);
			CREATE INDEX IF NOT EXISTS revision_cards_owner_due_idx ON revision_cards(owner_id, due_at);
			CREATE INDEX IF NOT EXISTS revision_cards_session_due_idx ON revision_cards(session_key, due_at);
		""")
		if not app.config["SECRET_KEY"]:
			row = db.execute("SELECT value FROM app_settings WHERE key = 'flask_secret_key'").fetchone()
			if row is None:
				db.execute(
					"INSERT OR IGNORE INTO app_settings(key, value) VALUES ('flask_secret_key', ?)",
					(secrets.token_urlsafe(48),),
				)
				row = db.execute("SELECT value FROM app_settings WHERE key = 'flask_secret_key'").fetchone()
			app.config["SECRET_KEY"] = row["value"]
	_db_ready = True


@app.before_request
def prepare_request():
	if not _db_ready:
		init_db()
	if "csrf_token" not in session:
		session["csrf_token"] = secrets.token_urlsafe(32)
	if "history_key" not in session:
		session["history_key"] = secrets.token_urlsafe(32)


def now():
	return datetime.now(timezone.utc).isoformat(timespec="seconds")


def fail(message, status=400):
	return jsonify({"error": message}), status


def data_scope(owner_id=None, table_alias=None):
	prefix = f"{table_alias}." if table_alias else ""
	if owner_id is None:
		return f"{prefix}owner_id IS NULL AND {prefix}session_key = ?", (session["history_key"],)
	return f"{prefix}owner_id = ?", (owner_id,)


def validated_topic(data):
	topic = str(data.get("topic", "")).strip()
	if not topic:
		raise ValueError("Enter a topic to get started.")
	if len(topic) > MAX_TOPIC_LENGTH:
		raise ValueError(f"Keep the topic under {MAX_TOPIC_LENGTH} characters.")
	return topic


def require_json(fn):
	@wraps(fn)
	def wrapper(*args, **kwargs):
		expected_token = session.get("csrf_token", "")
		provided_token = request.headers.get("X-CSRF-Token", "")
		if not expected_token or not hmac.compare_digest(expected_token, provided_token):
			return fail("Your session expired. Refresh the page and try again.", 403)
		data = request.get_json(silent=True)
		if not isinstance(data, dict):
			return fail("Please send a valid JSON request.")
		try:
			return fn(data, *args, **kwargs)
		except ValueError as exc:
			return fail(str(exc))
	return wrapper


def ask_model(system_prompt, user_prompt):
    api_key = os.environ.get("GEMINI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("AI is not configured yet. Set GEMINI_API_KEY on the server, then restart EduMirror.")
    
    # Initialize the Gemini client
    client = genai.Client(api_key=api_key)
    
    model = os.environ.get("GEMINI_MODEL", "gemini-3.6-flash")
    
    try:
        response = client.models.generate_content(
            model=model,
            contents=user_prompt,
            config={
                "system_instruction": system_prompt,
                "temperature": 0.6,
            }
        )
    except genai.errors.APIError as exc:
        raise RuntimeError(
            f"Gemini API request failed ({exc.code}): "
            f"{exc.message or 'Check the API key and model configuration.'}"
        ) from exc

    return response.text


def ai_json(system_prompt, user_prompt):
	raw = ask_model(system_prompt + " Return only valid JSON, without markdown fences.", user_prompt)
	raw = raw.strip()
	if raw.startswith("```"):
		raw = raw.split("\n", 1)[-1].rsplit("```", 1)[0].strip()
	try:
		return json.loads(raw)
	except json.JSONDecodeError as exc:
		raise RuntimeError("The AI returned an unreadable response. Please try again.") from exc


@app.errorhandler(500)
def server_error(_error):
	return jsonify({"error": "Something went wrong on the server. Please try again."}), 500


@app.get("/api/health")
def health():
	return jsonify({"ok": True, "ai_configured": bool(os.environ.get("GEMINI_API_KEY"))})


def auth_response(user):
	return jsonify({
		"authenticated": True,
		"username": user["username"],
		"email": user["email"],
		"csrf_token": session["csrf_token"],
	})


@app.get("/api/auth/status")
def auth_status():
	user_id = session.get("user_id")
	if user_id is None:
		return jsonify({"authenticated": False, "csrf_token": session["csrf_token"]})
	with connect_db() as db:
		user = db.execute("SELECT username, email FROM users WHERE id = ?", (user_id,)).fetchone()
	if user is None:
		session.clear()
		session["csrf_token"] = secrets.token_urlsafe(32)
		return jsonify({"authenticated": False, "csrf_token": session["csrf_token"]})
	return auth_response(user)


@app.post("/api/auth/signup")
@require_json
def signup(data):
	username = str(data.get("username", "")).strip()
	email = str(data.get("email", "")).strip().lower()
	password = data.get("password", "")
	if not re.fullmatch(r"[A-Za-z0-9_.-]{3,30}", username):
		raise ValueError("Username must be 3–30 characters using letters, numbers, dots, dashes, or underscores.")
	if len(email) > 254 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", email):
		raise ValueError("Enter a valid email address.")
	if not isinstance(password, str) or not 8 <= len(password) <= MAX_PASSWORD_LENGTH:
		raise ValueError(f"Password must be between 8 and {MAX_PASSWORD_LENGTH} characters.")
	with connect_db() as db:
		try:
			cursor = db.execute(
				"INSERT INTO users(username, username_key, email, email_key, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
				(username, username.casefold(), email, email, generate_password_hash(password), now()),
			)
		except sqlite3.IntegrityError:
			return fail("That username or email is already registered.", 409)
		history_key = session["history_key"]
		db.execute(
			"UPDATE explanation_history SET owner_id = ? WHERE owner_id IS NULL AND session_key = ?",
			(cursor.lastrowid, history_key),
		)
		db.execute(
			"UPDATE revision_cards SET owner_id = ? WHERE owner_id IS NULL AND session_key = ?",
			(cursor.lastrowid, history_key),
		)
		for table in ("learning_history", "quizzes", "quiz_results"):
			db.execute(f"UPDATE {table} SET owner_id = ? WHERE owner_id IS NULL AND session_key = ?", (cursor.lastrowid, history_key))
		user = db.execute("SELECT username, email FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
	session.clear()
	session["user_id"] = cursor.lastrowid
	session["history_key"] = history_key
	session["csrf_token"] = secrets.token_urlsafe(32)
	return auth_response(user), 201


@app.post("/api/auth/login")
@require_json
def login(data):
	identifier = str(data.get("identifier", "")).strip().casefold()
	password = data.get("password", "")
	if not identifier or len(identifier) > 254 or not isinstance(password, str) or not 1 <= len(password) <= MAX_PASSWORD_LENGTH:
		return fail("Enter your email or username and password.")
	with connect_db() as db:
		user = db.execute(
			"SELECT id, username, email, password_hash FROM users WHERE username_key = ? OR email_key = ?",
			(identifier, identifier),
		).fetchone()
	if user is None or not check_password_hash(user["password_hash"], password):
		return fail("Those sign-in details don't match an account.", 401)
	history_key = session["history_key"]
	with connect_db() as db:
		db.execute(
			"UPDATE explanation_history SET owner_id = ? WHERE owner_id IS NULL AND session_key = ?",
			(user["id"], history_key),
		)
		db.execute(
			"UPDATE revision_cards SET owner_id = ? WHERE owner_id IS NULL AND session_key = ?",
			(user["id"], history_key),
		)
		for table in ("learning_history", "quizzes", "quiz_results"):
			db.execute(f"UPDATE {table} SET owner_id = ? WHERE owner_id IS NULL AND session_key = ?", (user["id"], history_key))
	session.clear()
	session["user_id"] = user["id"]
	session["history_key"] = history_key
	session["csrf_token"] = secrets.token_urlsafe(32)
	return auth_response(user)


@app.post("/api/auth/logout")
@require_json
def logout(_data):
	session.clear()
	session["history_key"] = secrets.token_urlsafe(32)
	session["csrf_token"] = secrets.token_urlsafe(32)
	return jsonify({"ok": True, "csrf_token": session["csrf_token"]})


@app.post("/api/progress/clear")
@require_json
def clear_progress(data):
	if data.get("confirmed") is not True:
		return fail("Confirm that you want to clear this progress.")
	owner_id = session.get("user_id")
	scope_sql, scope_params = data_scope(owner_id)
	with connect_db() as db:
		for table in ("quiz_results", "learning_history", "quizzes"):
			db.execute(f"DELETE FROM {table} WHERE {scope_sql}", scope_params)
		if owner_id is None:
			db.execute("DELETE FROM revision_cards WHERE owner_id IS NULL AND session_key = ?", scope_params)
			db.execute("DELETE FROM explanation_history WHERE owner_id IS NULL AND session_key = ?", scope_params)
		else:
			db.execute("DELETE FROM revision_cards WHERE owner_id = ?", scope_params)
			db.execute("DELETE FROM explanation_history WHERE owner_id = ?", scope_params)
	return jsonify({"ok": True})


@app.post("/api/explain")
@require_json
def explain(data):
	topic = validated_topic(data)
	level = str(data.get("level", "Curious learner"))[:60]
	style = str(data.get("style", "simple"))
	styles = {"simple": "a simple, intuitive explanation", "steps": "a clear step-by-step walkthrough", "examples": "relatable real-life examples"}
	if style not in styles:
		raise ValueError("Choose one of the available learning styles.")
	try:
		result = ai_json(
			"You are an encouraging, accurate tutor. Adapt vocabulary to the learner. Avoid unsupported claims.",
			f"Topic: {topic}\nLearner level: {level}\nTeaching style: {styles[style]}. "
			'Return JSON with keys: title, overview (2-4 sentences), sections (array of 2-4 objects with heading and text), '
			'example, takeaways (array of 3 short strings), and diagram (a compact plain-text relationship or sequence, or empty string).',
		)
		with connect_db() as db:
			db.execute("INSERT INTO learning_history(owner_id, session_key, topic, activity, created_at) VALUES (?, ?, ?, ?, ?)",
					   (session.get("user_id"), session["history_key"], topic, "Explanation", now()))
			db.execute(
				"INSERT INTO explanation_history(owner_id, session_key, topic, level, style, result_json, created_at, activity_type) "
				"VALUES (?, ?, ?, ?, ?, ?, ?, 'explanation')",
				(session.get("user_id"), session["history_key"], topic, level, style, json.dumps(result), now()),
			)
		return jsonify(result)
	except RuntimeError as exc:
		return fail(str(exc), 503)


@app.get("/api/history")
def chat_history():
	owner_id = session.get("user_id")
	with connect_db() as db:
		if owner_id is None:
			rows = db.execute(
				"SELECT id, topic, activity_type, created_at FROM explanation_history "
				"WHERE owner_id IS NULL AND session_key = ? ORDER BY id DESC",
				(session["history_key"],),
			).fetchall()
		else:
			rows = db.execute(
				"SELECT id, topic, activity_type, created_at FROM explanation_history WHERE owner_id = ? ORDER BY id DESC",
				(owner_id,),
			).fetchall()
	return jsonify({"history": [dict(row) for row in rows]})


@app.get("/api/history/<int:entry_id>")
def chat_history_entry(entry_id):
	owner_id = session.get("user_id")
	with connect_db() as db:
		if owner_id is None:
			row = db.execute(
				"SELECT id, topic, level, style, result_json, activity_type, created_at FROM explanation_history "
				"WHERE id = ? AND owner_id IS NULL AND session_key = ?",
				(entry_id, session["history_key"]),
			).fetchone()
		else:
			row = db.execute(
				"SELECT id, topic, level, style, result_json, activity_type, created_at FROM explanation_history "
				"WHERE id = ? AND owner_id = ?",
				(entry_id, owner_id),
			).fetchone()
	if row is None:
		return fail("That activity isn't in your chat history.", 404)
	result = json.loads(row["result_json"])
	entry = {
		"topic": row["topic"],
		"activity_type": row["activity_type"],
		"level": row["level"],
		"style": row["style"],
		"result": result,
		"created_at": row["created_at"],
	}
	if row["activity_type"] == "quiz":
		scope_sql, scope_params = data_scope(owner_id)
		with connect_db() as db:
			quiz = db.execute(
				f"SELECT user_answers, completed FROM quizzes WHERE id = ? AND {scope_sql}",
				(result.get("quiz_id"), *scope_params),
			).fetchone()
			score = db.execute(
				f"SELECT score, total FROM quiz_results WHERE quiz_id = ? AND {scope_sql} ORDER BY id DESC LIMIT 1",
				(result.get("quiz_id"), *scope_params),
			).fetchone()
		entry["answers"] = json.loads(quiz["user_answers"]) if quiz else []
		entry["completed"] = bool(quiz and quiz["completed"])
		entry["score"] = dict(score) if score else None
	return jsonify(entry)


@app.post("/api/study")
@require_json
def study(data):
	topic = validated_topic(data)
	try:
		result = ai_json(
			"You create concise, accurate study material for students. Use plain language.",
			f"Create study tools for: {topic}. Return JSON with keys: summary (one paragraph), notes (array of 5-7 concise strings), "
			"practice (array of 3 questions, no answers), and memory_tip (one helpful mnemonic or strategy).",
		)
		with connect_db() as db:
			db.execute("INSERT INTO learning_history(owner_id, session_key, topic, activity, created_at) VALUES (?, ?, ?, ?, ?)",
					   (session.get("user_id"), session["history_key"], topic, "Study tools", now()))
			db.execute(
				"INSERT INTO explanation_history(owner_id, session_key, topic, level, style, result_json, created_at, activity_type) "
				"VALUES (?, ?, ?, '', '', ?, ?, 'study')",
				(session.get("user_id"), session["history_key"], topic, json.dumps(result), now()),
			)
		return jsonify(result)
	except RuntimeError as exc:
		return fail(str(exc), 503)


@app.post("/api/concept-map")
@require_json
def create_concept_map(data):
	topic = validated_topic(data)
	try:
		result = ai_json(
			"You are a careful tutor who builds accurate, easy-to-follow concept maps for students.",
			f"Build a concept map about: {topic}. Return JSON with a concepts array of 5 to 7 objects. "
			"Each concept must have label (2-32 characters) and description (one concise sentence, up to 240 characters). "
			"Also return connections: an array of pairs of zero-based concept indexes describing meaningful relationships. "
			"Include 5 to 10 connections, no self-connections, and keep all indexes within the concepts array.",
		)
		concepts = result.get("concepts") if isinstance(result, dict) else None
		connections = result.get("connections") if isinstance(result, dict) else None
		if not isinstance(concepts, list) or not 5 <= len(concepts) <= 7:
			raise RuntimeError("The AI did not create a usable concept map. Please try again.")
		for concept in concepts:
			if (not isinstance(concept, dict) or not isinstance(concept.get("label"), str)
					or not 2 <= len(concept["label"].strip()) <= 32
					or not isinstance(concept.get("description"), str)
					or not 1 <= len(concept["description"].strip()) <= 240):
				raise RuntimeError("The AI created an invalid concept map. Please try again.")
		if not isinstance(connections, list) or not 5 <= len(connections) <= 10:
			raise RuntimeError("The AI did not connect the concepts clearly. Please try again.")
		validated_connections = []
		for connection in connections:
			if (not isinstance(connection, list) or len(connection) != 2
					or any(type(index) is not int or index not in range(len(concepts)) for index in connection)
					or connection[0] == connection[1]):
				raise RuntimeError("The AI created invalid concept-map connections. Please try again.")
			pair = sorted(connection)
			if pair not in validated_connections:
				validated_connections.append(pair)
		if len(validated_connections) < 5:
			raise RuntimeError("The AI did not create enough unique concept-map connections. Please try again.")
		with connect_db() as db:
			db.execute(
				"INSERT INTO learning_history(owner_id, session_key, topic, activity, created_at) VALUES (?, ?, ?, ?, ?)",
				(session.get("user_id"), session["history_key"], topic, "Concept map", now()),
			)
			map_result = {"topic": topic, "concepts": concepts, "connections": validated_connections}
			db.execute(
				"INSERT INTO explanation_history(owner_id, session_key, topic, level, style, result_json, created_at, activity_type) "
				"VALUES (?, ?, ?, '', '', ?, ?, 'concept_map')",
				(session.get("user_id"), session["history_key"], topic, json.dumps(map_result), now()),
			)
		return jsonify(map_result)
	except RuntimeError as exc:
		return fail(str(exc), 503)


@app.post("/api/quiz")
@require_json
def create_quiz(data):
	topic = validated_topic(data)
	try:
		result = ai_json(
			"You write fair, educational multiple-choice questions. Each question has exactly four distinct choices and one correct answer.",
			f"Create a 5-question quiz about {topic}. Return JSON with a questions array; each item must have question, "
			"choices (array of exactly four strings), answer (zero-based integer index), and explanation (one or two sentences).",
		)
		questions = result.get("questions") if isinstance(result, dict) else None
		if not isinstance(questions, list) or not 3 <= len(questions) <= 8:
			raise RuntimeError("The AI did not create a usable quiz. Please try again.")
		for q in questions:
			choices = q.get("choices") if isinstance(q, dict) else None
			if (
				not isinstance(q, dict)
				or not isinstance(q.get("question"), str)
				or not 1 <= len(q["question"].strip()) <= 500
				or not isinstance(choices, list)
				or len(choices) != 4
				or any(not isinstance(choice, str) or not 1 <= len(choice.strip()) <= 180 for choice in choices)
				or len({choice.strip().casefold() for choice in choices if isinstance(choice, str)}) != 4
				or type(q.get("answer")) is not int
				or q["answer"] not in range(4)
				or not isinstance(q.get("explanation"), str)
				or len(q["explanation"]) > 1000
			):
				raise RuntimeError("The AI created an invalid quiz. Please try again.")
		quiz_id = str(uuid.uuid4())
		with connect_db() as db:
			db.execute("INSERT INTO quizzes(id, owner_id, session_key, topic, questions, created_at) VALUES (?, ?, ?, ?, ?, ?)",
					   (quiz_id, session.get("user_id"), session["history_key"], topic, json.dumps(questions), now()))
			db.execute("INSERT INTO learning_history(owner_id, session_key, topic, activity, created_at) VALUES (?, ?, ?, ?, ?)",
					   (session.get("user_id"), session["history_key"], topic, "Quiz", now()))
			db.execute(
				"INSERT INTO explanation_history(owner_id, session_key, topic, level, style, result_json, created_at, activity_type) "
				"VALUES (?, ?, ?, '', '', ?, ?, 'quiz')",
				(session.get("user_id"), session["history_key"], topic,
				 json.dumps({"quiz_id": quiz_id, "questions": questions}), now()),
			)
		public_questions = [{"question": q.get("question", ""), "choices": q["choices"]} for q in questions]
		return jsonify({"quiz_id": quiz_id, "topic": topic, "questions": public_questions})
	except RuntimeError as exc:
		return fail(str(exc), 503)


@app.post("/api/quiz/check")
@require_json
def check_answer(data):
	quiz_id = str(data.get("quiz_id", ""))
	index, answer = data.get("index"), data.get("answer")
	if type(index) is not int or type(answer) is not int or answer not in range(4):
		raise ValueError("That answer could not be checked. Please choose an option.")
	owner_id = session.get("user_id")
	scope_sql, scope_params = data_scope(owner_id)
	with connect_db() as db:
		row = db.execute(
			f"SELECT questions, user_answers, completed FROM quizzes WHERE id = ? AND {scope_sql}",
			(quiz_id, *scope_params),
		).fetchone()
		if not row:
			return fail("This quiz has expired. Please create a new one.", 404)
		questions, answers = json.loads(row["questions"]), json.loads(row["user_answers"])
		if row["completed"] or index not in range(len(questions)):
			return fail("This quiz question is no longer available.", 409)
		next_index = next((position for position, previous_answer in enumerate(answers) if previous_answer is None), len(answers))
		if index < next_index:
			if index >= len(answers) or answers[index] != answer:
				return fail("This quiz question has already been answered.", 409)
		elif index != next_index:
			return fail("Answer the quiz questions in order, one at a time.", 409)
		correct = answer == questions[index]["answer"]
		if index == next_index:
			while len(answers) < len(questions):
				answers.append(None)
			answers[index] = answer
			db.execute("UPDATE quizzes SET user_answers = ? WHERE id = ?", (json.dumps(answers), quiz_id))
	q = questions[index]
	return jsonify({"correct": correct, "correct_answer": q["answer"], "explanation": q.get("explanation", "")})


@app.post("/api/quiz/finish")
@require_json
def finish_quiz(data):
	quiz_id = str(data.get("quiz_id", ""))
	owner_id = session.get("user_id")
	scope_sql, scope_params = data_scope(owner_id)
	with connect_db() as db:
		row = db.execute(
			f"SELECT topic, questions, user_answers, completed FROM quizzes WHERE id = ? AND {scope_sql}",
			(quiz_id, *scope_params),
		).fetchone()
		if not row:
			return fail("This quiz has expired. Please create a new one.", 404)
		questions, answers = json.loads(row["questions"]), json.loads(row["user_answers"])
		if not row["completed"] and (len(answers) < len(questions) or any(answer is None for answer in answers)):
			return fail("Answer every question before finishing the quiz.", 409)
		score = sum(1 for i, q in enumerate(questions) if i < len(answers) and answers[i] == q["answer"])
		if not row["completed"]:
			db.execute("UPDATE quizzes SET completed = 1 WHERE id = ?", (quiz_id,))
			db.execute("INSERT INTO quiz_results(owner_id, session_key, quiz_id, topic, score, total, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
					   (owner_id, session["history_key"], quiz_id, row["topic"], score, len(questions), now()))
			for index, question in enumerate(questions):
				user_answer = answers[index] if index < len(answers) else None
				if user_answer is None or user_answer == question["answer"]:
					continue
				db.execute(
					"INSERT OR IGNORE INTO revision_cards "
					"(id, owner_id, session_key, quiz_id, topic, question, choices, correct_answer, "
					"user_answer, explanation, due_at, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
					(
						f"{quiz_id}:{index}", session.get("user_id"), session["history_key"], quiz_id,
						row["topic"], question.get("question", ""), json.dumps(question["choices"]),
						question["answer"], user_answer, question.get("explanation", ""), now(), now(),
					),
				)
		return jsonify({"score": score, "total": len(questions), "topic": row["topic"]})


@app.get("/api/revision")
def revision():
	owner_id = session.get("user_id")
	scope_sql, scope_params = data_scope(owner_id)
	with connect_db() as db:
		stats = db.execute(
			f"SELECT COUNT(*) AS total, SUM(mastered) AS mastered, "
			f"SUM(CASE WHEN due_at <= ? THEN 1 ELSE 0 END) AS due FROM revision_cards WHERE {scope_sql}",
			(now(), *scope_params),
		).fetchone()
		cards = db.execute(
			f"SELECT id, topic, question, choices, correct_answer, user_answer, explanation, "
			f"review_count FROM revision_cards WHERE {scope_sql} AND due_at <= ? "
			"ORDER BY due_at ASC, created_at ASC",
			(*scope_params, now()),
		).fetchall()
		result_scope, result_params = data_scope(owner_id)
		weak_topics = db.execute(
			"SELECT topic, ROUND(100.0 * SUM(score) / NULLIF(SUM(total), 0)) AS mastery, "
			f"COUNT(*) AS quizzes FROM quiz_results WHERE {result_scope} GROUP BY topic "
			"HAVING SUM(total) > 0 ORDER BY mastery ASC, quizzes DESC, MAX(created_at) DESC LIMIT 5",
			result_params,
		).fetchall()
	return jsonify({
		"due_count": stats["due"] or 0,
		"total_cards": stats["total"] or 0,
		"mastered_cards": stats["mastered"] or 0,
		"cards": [{
			"id": card["id"],
			"topic": card["topic"],
			"question": card["question"],
			"choices": json.loads(card["choices"]),
			"correct_answer": card["correct_answer"],
			"user_answer": card["user_answer"],
			"explanation": card["explanation"],
			"review_count": card["review_count"],
		} for card in cards],
		"weak_topics": [dict(topic) for topic in weak_topics],
	})


@app.post("/api/revision/review")
@require_json
def review_revision_card(data):
	card_id = data.get("card_id")
	action = data.get("action")
	if not isinstance(card_id, str) or not 1 <= len(card_id) <= 80:
		raise ValueError("Choose a revision card to review.")
	if not isinstance(action, str) or action not in {"again", "got_it"}:
		raise ValueError("Choose whether to review this card again or mark it as known.")
	owner_id = session.get("user_id")
	with connect_db() as db:
		if owner_id is None:
			card = db.execute(
				"SELECT id FROM revision_cards WHERE id = ? AND owner_id IS NULL AND session_key = ?",
				(card_id, session["history_key"]),
			).fetchone()
		else:
			card = db.execute(
				"SELECT id FROM revision_cards WHERE id = ? AND owner_id = ?",
				(card_id, owner_id),
			).fetchone()
		if card is None:
			return fail("That revision card is no longer available.", 404)
		due_at = now() if action == "again" else (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(timespec="seconds")
		db.execute(
			"UPDATE revision_cards SET due_at = ?, review_count = review_count + 1, mastered = ? WHERE id = ?",
			(due_at, int(action == "got_it"), card_id),
		)
		scope_sql, scope_params = data_scope(owner_id)
		stats = db.execute(
			"SELECT COUNT(*) AS total, SUM(mastered) AS mastered, "
			f"SUM(CASE WHEN due_at <= ? THEN 1 ELSE 0 END) AS due FROM revision_cards WHERE {scope_sql}",
			(now(), *scope_params),
		).fetchone()
	return jsonify({
		"due_count": stats["due"] or 0,
		"total_cards": stats["total"] or 0,
		"mastered_cards": stats["mastered"] or 0,
	})


@app.get("/api/progress")
def progress():
	owner_id = session.get("user_id")
	history_scope, history_params = data_scope(owner_id)
	results_scope, results_params = data_scope(owner_id)
	topics_history_scope, topics_history_params = data_scope(owner_id, "history")
	topics_results_scope, topics_results_params = data_scope(owner_id, "quiz_results")
	with connect_db() as db:
		studied = db.execute(f"SELECT COUNT(*) FROM learning_history WHERE {history_scope}", history_params).fetchone()[0]
		results = db.execute(f"SELECT score, total FROM quiz_results WHERE {results_scope}", results_params).fetchall()
		topics = db.execute(
			"SELECT history.topic, MAX(history.created_at) AS last_seen, COUNT(*) AS sessions, "
			"MAX(scores.mastery) AS mastery FROM learning_history AS history "
			f"LEFT JOIN (SELECT topic, ROUND(100.0 * SUM(score) / NULLIF(SUM(total), 0)) AS mastery "
			f"FROM quiz_results WHERE {topics_results_scope} GROUP BY topic) AS scores ON scores.topic = history.topic "
			f"WHERE {topics_history_scope} GROUP BY history.topic ORDER BY last_seen DESC LIMIT 6",
			(*topics_results_params, *topics_history_params),
		).fetchall()
	total_correct = sum(r["score"] for r in results)
	total_questions = sum(r["total"] for r in results)
	return jsonify({"activities": studied, "quizzes": len(results), "accuracy": round(total_correct * 100 / total_questions) if total_questions else 0,
					"topics": [dict(r) for r in topics]})


PAGE = r'''<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="csrf-token" content="{{ csrf_token }}">
<meta name="theme-color" content="#100d24"><meta name="description" content="StuDyEaSe &mdash; Understand EASY. Learn More. Make learning personal with thoughtful AI explanations, quizzes, and study tools.">
<link rel="manifest" href="/manifest.webmanifest"><link rel="icon" href="/app-icon.svg" type="image/svg+xml">
<title>StuDyEaSe &mdash; Understand EASY. Learn More.</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Serif+Display:ital@0;1&display=swap" rel="stylesheet">
<style>
:root{--display:'DM Serif Display',Georgia,'Times New Roman',serif;--font:'DM Sans',Arial,sans-serif;--caps:.2em;--content:1080px;--header-height:108px}
*{box-sizing:border-box}html{scroll-behavior:smooth;scroll-padding-top:calc(var(--header-height) + 22px);-webkit-text-size-adjust:100%}body{margin:0;min-width:320px;background:var(--paper);color:var(--ink);font:400 17px/1.65 var(--font);-webkit-font-smoothing:antialiased;overflow-x:hidden}body:before{content:"";position:fixed;inset:0;z-index:-2;pointer-events:none;background:radial-gradient(ellipse at 50% 10%,rgba(255,255,255,.6),transparent 54%),radial-gradient(ellipse at 10% 35%,rgba(86,137,184,.09),transparent 45%),repeating-linear-gradient(0deg,rgba(40,75,108,.025) 0 1px,transparent 1px 4px)}
a{color:inherit;text-decoration:none}button,input,select{font:inherit;color:inherit}button{touch-action:manipulation}::selection{background:rgba(149,104,63,.24);color:var(--ink)}:focus-visible{outline:2px solid var(--earth);outline-offset:4px}
.top{position:fixed;z-index:50;inset:0 0 auto;display:flex;flex-direction:column;align-items:center;gap:10px;padding:16px 24px 44px;text-align:center;pointer-events:none}.top:before{content:"";position:absolute;inset:0;z-index:-1;background:linear-gradient(180deg,rgba(220,232,244,.97),rgba(220,232,244,.84) 56%,rgba(220,232,244,0));backdrop-filter:blur(12px);mask-image:linear-gradient(#000 0 62%,transparent)}.top>*{pointer-events:auto}.name{font:400 clamp(25px,2.4vw,31px)/1 var(--display);letter-spacing:.015em;white-space:nowrap}.name-mark{display:inline-grid;width:24px;height:24px;margin-right:8px;place-items:center;vertical-align:middle;border:1px solid var(--earth);border-radius:50%;color:var(--earth);font:13px/1 var(--font)}.top nav{display:flex;align-items:center;justify-content:center;gap:clamp(16px,2.5vw,32px);font-size:14px;letter-spacing:.055em}.top nav a{color:var(--ink-soft);transition:color .2s}.top nav a:hover,.top nav a[aria-current="location"]{color:var(--ink)}.top nav .nav-start{padding:5px 0;border-bottom:1px solid rgba(66,111,157,.52);color:var(--earth)}
 .hero{position:relative;isolation:isolate;display:flex;min-height:100svh;flex-direction:column;align-items:center;justify-content:center;padding:calc(var(--header-height) + 8px) 0 60px;text-align:center;overflow:hidden}.hero:before,.hero:after{content:"";position:absolute;z-index:-1;bottom:4%;width:clamp(150px,19vw,250px);height:clamp(240px,29vw,365px);opacity:.4;pointer-events:none;background:center/contain no-repeat url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 220 340' fill='none' stroke='%2395683f' stroke-opacity='.62' stroke-width='1.5'%3E%3Cpath d='M20 325C72 262 63 194 109 111 128 75 157 41 198 16M76 224c-37-2-59-25-55-55 30-4 52 13 55 55Zm23-53c-4-35 13-58 42-64 8 28-6 51-42 64Zm28-61c-3-31 14-50 39-56 7 23-7 44-39 56ZM48 277c-30-6-45-27-39-51 26 1 42 19 39 51Z'/%3E%3Ccircle cx='198' cy='16' r='5'/%3E%3C/svg%3E")}.hero:before{left:clamp(-55px,1vw,28px);transform:rotate(-7deg)}.hero:after{right:clamp(-45px,2vw,45px);bottom:1%;transform:scaleX(-1) rotate(-3deg);filter:hue-rotate(35deg)}
.hero-kicker,.section-label{margin:0;color:var(--ink-faint);font-size:11px;letter-spacing:var(--caps);text-transform:uppercase}.hero h1{max-width:850px;margin:17px 20px 14px;font:400 clamp(48px,7vw,80px)/.98 var(--display);letter-spacing:-.025em}.hero h1 em{color:var(--earth);font-weight:400}.hero-intro{max-width:560px;margin:0 24px 18px;color:var(--ink-soft);font-size:clamp(17px,1.9vw,20px);font-weight:300;line-height:1.55}
.primary{display:inline-flex;min-height:42px;align-items:center;justify-content:center;gap:8px;padding:9px 20px;border:1px solid #426f9d;border-radius:999px;background:#426f9d;color:#faf5e9;font-size:14px;line-height:1.2;cursor:pointer;transition:background .2s,border-color .2s,transform .2s}.primary:hover{transform:translateY(-1px);border-color:#315c87;background:#315c87}.primary:disabled{opacity:.62;cursor:wait;transform:none}.hint{margin:10px 0 0;color:var(--ink-faint);font-size:12px}.hero-down{position:absolute;bottom:17px;left:50%;display:grid;width:42px;height:42px;transform:translateX(-50%);place-items:center;border:0;background:transparent;color:var(--ink-faint);cursor:pointer;animation:breathe 2.8s ease-in-out infinite}.hero-down:hover{color:var(--earth);animation:none}@keyframes breathe{0%,100%{opacity:.2}50%{opacity:.8}}
.rule{position:relative;display:block;width:min(930px,82vw);height:24px;margin:28px auto 54px}.rule:before{content:"";position:absolute;top:50%;left:0;right:0;height:1px;background:linear-gradient(90deg,transparent,var(--hairline) 14%,var(--hairline) 86%,transparent)}.rule:after{position:absolute;top:50%;left:50%}.rule.short{width:min(440px,60vw);margin:44px auto}.section-label{margin:0 0 15px;font-size:10px}.section-title{margin:0 0 12px;font:400 clamp(36px,5vw,57px)/1.05 var(--display);letter-spacing:-.015em}.section-copy{max-width:660px;margin:0;color:var(--ink-soft);font-size:18px;font-weight:300;line-height:1.7}
.about,.capabilities,.progress{max-width:var(--content);margin:0 auto;padding:4px clamp(22px,5vw,52px) 10px}.about{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:clamp(30px,6vw,76px)}.about-copy{max-width:650px}.about-mark{width:clamp(145px,18vw,220px);height:auto;opacity:.9}.plate-list{margin:20px 0 0;padding:0;border-top:1px solid var(--hairline);list-style:none}.plate{display:grid;grid-template-columns:3.5em minmax(0,1fr) minmax(120px,auto);align-items:baseline;gap:15px;padding:17px 5px;border-bottom:1px solid var(--hairline);transition:background-color .2s,padding-left .2s}.plate:hover{padding-left:12px;background:rgba(255,252,244,.52)}.plate .n{color:var(--ink-faint);font-size:12px;letter-spacing:.1em;font-variant-numeric:tabular-nums}.plate .t{font:400 clamp(21px,2.2vw,28px)/1.2 var(--display)}.plate .p{color:var(--ink-faint);font-size:12px;letter-spacing:.09em;text-align:right;text-transform:uppercase}.plate:hover .p{color:var(--earth)}
.studio{max-width:var(--content);margin:0 auto;padding:0 clamp(22px,5vw,52px)}.studio-heading{display:grid;grid-template-columns:minmax(0,.9fr) minmax(0,1.1fr);align-items:end;gap:26px;margin-bottom:27px}.studio-heading .section-copy{font-size:16px}.studio-paper{position:relative;padding:clamp(21px,4vw,42px);border:1px solid rgba(74,56,34,.19);border-radius:4px;background:linear-gradient(120deg,rgba(255,255,255,.44),rgba(255,252,244,.73));box-shadow:0 12px 35px rgba(65,47,26,.08),inset 0 0 0 5px rgba(255,255,255,.2)}.studio-paper:before{content:"";position:absolute;inset:12px;pointer-events:none;border:1px solid rgba(74,56,34,.08)}.studio-paper>*{position:relative}.controls{display:grid;grid-template-columns:minmax(0,1fr) minmax(150px,.43fr) auto;align-items:end;gap:15px}.field label{display:block;margin:0 0 7px 2px;color:var(--ink-soft);font-size:12px;letter-spacing:.055em}.field input,.field select{display:block;width:100%;height:46px;padding:0 13px;border:1px solid rgba(43,39,33,.2);border-radius:3px;outline:0;background:rgba(250,248,241,.88);color:var(--ink);font-size:15px;transition:border-color .2s,box-shadow .2s}.controls>.primary{min-height:46px;border-radius:3px;white-space:nowrap}
.style-tabs{display:flex;gap:9px;flex-wrap:wrap;margin-top:18px}.style-tab{padding:7px 12px;border:1px solid transparent;border-bottom-color:var(--hairline);background:transparent;color:var(--ink-soft);font-size:13px;cursor:pointer;transition:color .18s,border-color .18s,background .18s}.style-tab:hover{color:var(--ink);border-color:rgba(149,104,63,.28)}.style-tab.active{border-color:rgba(149,104,63,.28);background:rgba(149,104,63,.085);color:var(--earth)}.output{min-height:36px;margin-top:19px}.empty{padding:20px 17px;border:1px dashed rgba(43,39,33,.23);color:var(--ink-soft);font-size:14px;line-height:1.7;text-align:center}.loader{display:inline-block;width:14px;height:14px;margin-right:8px;vertical-align:-2px;border:1.5px solid rgba(149,104,63,.22);border-top-color:var(--earth);border-radius:50%;animation:spin .75s linear infinite}@keyframes spin{to{transform:rotate(360deg)}}.result-card{padding:clamp(18px,3vw,30px);border-left:2px solid rgba(149,104,63,.52);background:rgba(255,252,245,.52)}.result-card h3{margin:0 0 12px;font:400 clamp(28px,4vw,39px)/1.12 var(--display)}.result-card h4{margin:22px 0 6px;color:var(--earth);font-size:11px;font-weight:500;letter-spacing:var(--caps);text-transform:uppercase}.result-card p{margin:0 0 14px;color:var(--ink-soft);font-size:16px;line-height:1.75}.takeaways{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin-top:12px}.takeaways div{padding:12px 13px;border-top:1px solid rgba(149,104,63,.28);background:rgba(236,231,220,.42);font-size:14px;line-height:1.55}.diagram{padding:16px;border:1px solid var(--hairline);background:rgba(236,231,220,.55);color:var(--sage);font:14px/1.7 var(--font);white-space:pre-wrap}
.split{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));align-items:stretch;gap:24px;margin-top:28px}.tool-card{position:relative;padding:clamp(22px,3vw,32px);border:1px solid rgba(43,39,33,.17);background:rgba(248,245,237,.54);box-shadow:0 8px 25px rgba(65,47,26,.045)}.tool-card:after{content:"";position:absolute;top:0;left:20px;width:45px;height:2px;background:#b7885b}.tool-card h3{margin:0 0 8px;font:400 28px/1.15 var(--display)}.tool-card .subtle{margin:0;color:var(--ink-soft);font-size:15px;font-weight:300;line-height:1.65}.tool-card .field{margin:18px 0 14px}.tool-card>.primary{border-radius:3px}.notes-list{padding-left:22px;color:var(--ink-soft);font-size:15px;line-height:1.8}.notes-list li{padding:3px 0 3px 4px}.quiz-area{min-height:155px}.quiz-question{margin:6px 0 16px;font:400 clamp(23px,3vw,31px)/1.25 var(--display)}.quiz-footer{display:flex;align-items:center;justify-content:space-between;gap:12px;margin:12px 0}.pill{padding:3px 8px;border:1px solid var(--hairline);color:var(--ink-faint);font-size:11px;letter-spacing:.04em}.choice{display:block;width:100%;margin:6px 0;padding:11px 13px;border:1px solid rgba(43,39,33,.18);border-radius:2px;background:rgba(255,252,245,.6);text-align:left;cursor:pointer;transition:border-color .18s,background .18s}.choice:disabled{cursor:default}.feedback{margin:12px 0;color:var(--ink-soft);font-size:14px;line-height:1.65}
.progress-paper{margin-top:25px;padding:clamp(20px,4vw,40px);border-top:1px solid var(--hairline);border-bottom:1px solid var(--hairline);background:rgba(255,252,245,.34)}.progress-grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr))}.metric{padding:12px 20px;text-align:center;border-right:1px solid var(--hairline)}.metric:first-child{padding-left:0}.metric:last-child{padding-right:0;border-right:0}.metric strong{display:block;color:var(--earth);font:400 clamp(40px,6vw,65px)/1.1 var(--display);font-variant-numeric:tabular-nums}.metric span{display:block;margin-top:6px;color:var(--ink-faint);font-size:11px;letter-spacing:.11em;text-transform:uppercase}.topic-list{margin-top:26px;border-top:1px solid var(--hairline)}.topic-row{display:flex;justify-content:space-between;gap:15px;padding:12px 3px;border-bottom:1px solid var(--hairline);color:var(--ink-soft);font-size:15px}.topic-row span:last-child{color:var(--ink-faint);font-size:12px;letter-spacing:.06em}
footer{max-width:var(--content);margin:32px auto 0;padding:27px clamp(22px,5vw,52px) 34px;border-top:1px solid var(--hairline)}.footer-row{display:flex;align-items:center;justify-content:space-between;gap:18px}.footer-row .brand{font:400 22px var(--display)}.footer-row .logo{display:inline-grid;width:24px;height:24px;margin-right:7px;place-items:center;border:1px solid var(--earth);border-radius:50%;color:var(--earth);font:12px var(--font)}.foot-links{display:flex;flex-wrap:wrap;gap:18px;font-size:13px;color:var(--ink-soft)}.foot-links a:hover,.footer-row .nav-cta{color:var(--earth)}.footer-row .nav-cta{font-size:13px}.fine{margin:23px 0 0;color:var(--ink-faint);font-size:11px;line-height:1.7;text-align:center}.toast{position:fixed;right:22px;bottom:22px;z-index:80;max-width:min(420px,calc(100vw - 32px));padding:12px 17px;border:1px solid var(--hairline);background:var(--paper-light);box-shadow:0 12px 30px rgba(43,39,33,.14);color:var(--ink);font-size:14px;opacity:0;pointer-events:none;transform:translateY(8px);transition:opacity .2s,transform .2s}.toast.show{opacity:1;transform:translateY(0)}.reveal{opacity:0;transform:translateY(12px);transition:opacity .6s ease,transform .6s ease}.reveal.visible{opacity:1;transform:translateY(0)}
@media(max-width:900px){:root{--header-height:100px}.hero:before,.hero:after{opacity:.22}.studio-heading{grid-template-columns:1fr;gap:8px}.controls{grid-template-columns:minmax(0,1fr) minmax(145px,.55fr)}.controls>.primary{grid-column:1/-1}}
@media(max-width:680px){:root{--header-height:76px}.top{gap:8px;padding:13px 12px 35px}.name{font-size:23px}.hero{min-height:auto;padding:calc(var(--header-height) + 40px) 0 72px}.hero h1{font-size:clamp(48px,12vw,69px);margin:14px 12px 11px}.hero-kicker{font-size:9px;letter-spacing:.15em}.hero-intro{font-size:17px}.hero:before,.hero:after{display:none}.hint{font-size:11px}.hero-down{bottom:12px}.rule{margin:20px auto 39px}.rule.short{margin:32px auto}.about{grid-template-columns:1fr;gap:20px}.about-mark{width:130px;justify-self:center}.section-title{font-size:42px}.section-copy{font-size:16px}.plate{grid-template-columns:2.6em minmax(0,1fr);gap:9px;padding:14px 3px}.plate .p{grid-column:2;text-align:left;font-size:10px}.split{grid-template-columns:1fr}.controls{grid-template-columns:1fr}.controls>.primary{grid-column:auto}.style-tabs{gap:6px}.style-tab{padding:7px 9px;font-size:12px}.takeaways{grid-template-columns:1fr}.studio-paper{padding:19px}.studio-paper:before{inset:7px}.progress-paper{padding:18px 12px}.metric{padding:8px}.metric strong{font-size:44px}.metric span{font-size:9px;letter-spacing:.06em}.topic-row{font-size:14px}.footer-row{flex-wrap:wrap;justify-content:flex-start}.foot-links{order:3;width:100%;gap:12px 18px}.footer-row .nav-cta{margin-left:auto}.fine{text-align:left}}
@media(min-width:681px) and (max-width:1100px){:root{--header-height:150px}}
@media(prefers-reduced-motion:reduce){*,*::before,*::after{scroll-behavior:auto!important;animation-duration:.01ms!important;animation-iteration-count:1!important;transition-duration:.01ms!important}.reveal{opacity:1;transform:none}}
.result-card p,.notes-list,.takeaways div,.diagram,.feedback,.output>.empty{color:var(--ink)}
.result-card h4{color:var(--earth);font-weight:600}
.feedback{color:var(--ink);font-weight:500}


.result-card,.tool-card,.output{min-width:0}
.diagram,.notes-list,.takeaways div,.result-card p{overflow-wrap:anywhere}
@media(max-width:680px){
  .result-card{padding:18px 15px}
  .result-card p{font-size:16px;line-height:1.7}
  .result-card h3{font-size:clamp(27px,8vw,34px);overflow-wrap:anywhere}
  .result-card h4{font-size:10px}
  .diagram{padding:12px;font-size:13px}
  .notes-list{font-size:15px}
  .quiz-footer{align-items:flex-start;flex-wrap:wrap}
  .pill{font-size:12px;line-height:1.4}
  .choice{min-height:46px;padding:12px}
}
:root{color-scheme:dark}


::selection{background:rgba(255,121,92,.28)}

.name,.footer-row .brand{font-family:var(--font);font-weight:700;letter-spacing:-.055em}
.name-mark,.footer-row .logo{width:34px;height:34px;margin-right:9px;border:0;border-radius:11px;background:linear-gradient(140deg,var(--earth),#8a57f5 58%,var(--accent));box-shadow:0 5px 13px rgba(85,69,232,.22);font-size:0}
.footer-row .logo:before{content:"";width:22px;height:22px;background:center/contain no-repeat url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='white' stroke-width='1.7' stroke-linecap='round' stroke-linejoin='round'%3E%3Cpath d='M3 5.5c3.3-.9 6.3-.3 9 1.8v12c-2.7-2.1-5.7-2.7-9-1.8zM21 5.5c-3.3-.9-6.3-.3-9 1.8v12c2.7-2.1 5.7-2.7 9-1.8z'/%3E%3Cpath d='M17.7 2.5v4m-2-2h4'/%3E%3C/svg%3E")}
.hero h1 em{color:var(--earth)}
.learning-orbit{width:min(620px,80vw);margin:4px auto 10px;filter:drop-shadow(0 22px 24px rgba(67,49,150,.14))}
.learning-orbit svg{display:block;width:100%;height:auto;overflow:visible}
.orbit-track{fill:none;stroke:rgba(85,69,232,.19);stroke-width:1.5;stroke-dasharray:3 8}
.orbit-link{fill:none;stroke:rgba(85,69,232,.2);stroke-width:1.5}
.learning-orbit-mobile{display:none}
.orbit-node{animation:orbit-float 4s ease-in-out infinite;cursor:pointer;transition:filter .2s ease,scale .2s ease,translate .2s ease;transform-box:fill-box;transform-origin:center}
.orbit-node:hover,.orbit-node:focus-visible{animation-play-state:paused}
.orbit-card-node:hover,.orbit-card-node:focus-visible,.orbit-card-node[aria-pressed="true"]{filter:drop-shadow(0 0 10px rgba(85,69,232,.48));scale:1.08;translate:0 -5px}
.orbit-card-node:hover .orbit-card,.orbit-card-node[aria-pressed="true"] .orbit-card{fill:#fff;stroke:var(--accent);stroke-width:2}
.orbit-card-node:hover .orbit-icon,.orbit-card-node[aria-pressed="true"] .orbit-icon{stroke:var(--accent)}
.orbit-node:focus-visible{outline:none}
.orbit-card-node:focus-visible .orbit-card{stroke:var(--earth);stroke-width:3}
.idea-node:hover,.idea-node:focus-visible,.idea-node[aria-pressed="true"]{filter:drop-shadow(0 0 15px rgba(85,69,232,.72));scale:1.08}
.idea-node:focus-visible .idea-glow{stroke:#ff795c;stroke-width:4}
.orbit-dialog{width:min(430px,calc(100% - 36px));max-width:none;padding:28px;border:1px solid rgba(85,69,232,.2);border-radius:20px;background:linear-gradient(145deg,#fff 0%,#f6f2ff 100%);box-shadow:0 25px 80px rgba(39,31,94,.28);color:var(--ink);overflow:visible}
.orbit-dialog[open]{animation:orbit-popup .28s cubic-bezier(.2,.8,.25,1) both}
.orbit-dialog::backdrop{background:rgba(25,25,57,.4);backdrop-filter:blur(5px)}
.orbit-dialog h2{margin:4px 0 10px;color:#30285f;font:600 22px/1.25 var(--font)}
.orbit-dialog p{margin:0;color:var(--ink-soft);font-size:15px;line-height:1.7}
.orbit-dialog a{display:inline-flex;align-items:center;gap:7px;margin-top:20px;padding:10px 16px;border-radius:999px;background:linear-gradient(110deg,var(--earth),#7758ed);color:#fff;font-size:14px;font-weight:600}
.orbit-dialog a:hover{box-shadow:0 5px 16px rgba(85,69,232,.25)}
.orbit-dialog-close{position:absolute;top:12px;right:12px;display:grid;width:34px;height:34px;place-items:center;border:1px solid rgba(85,69,232,.15);border-radius:50%;background:#fff;color:#5545e8;font-size:20px;line-height:1;cursor:pointer}

.top .account-button{position:absolute;top:15px;right:clamp(16px,4vw,48px);padding:9px 15px;border:1px solid rgba(85,69,232,.2);border-radius:999px;background:rgba(255,255,255,.82);color:var(--earth);font-size:13px;font-weight:600;cursor:pointer}

.account-dialog{width:min(440px,calc(100% - 32px));max-width:none;padding:clamp(20px,5vw,32px);border:1px solid rgba(85,69,232,.2);border-radius:20px;background:linear-gradient(145deg,#fff,#f6f2ff);box-shadow:0 25px 80px rgba(39,31,94,.28);color:var(--ink)}
.account-dialog[open]{animation:orbit-popup .28s cubic-bezier(.2,.8,.25,1) both}
.account-dialog::backdrop{background:rgba(25,25,57,.4);backdrop-filter:blur(5px)}
.account-dialog [hidden]{display:none!important}
.account-dialog h2{margin:0 38px 8px 0;color:#30285f;font:600 24px/1.2 var(--font)}
.account-dialog .account-intro{margin:0 0 18px;color:var(--ink-soft);font-size:14px}
.account-tabs{display:flex;gap:8px;margin-bottom:16px;padding:4px;border-radius:12px;background:#efedfa}
.account-tabs button{flex:1;padding:9px;border:0;border-radius:9px;background:transparent;color:var(--ink-soft);font-size:13px;cursor:pointer}
.account-tabs button[aria-pressed="true"]{background:#fff;color:var(--earth);box-shadow:0 2px 8px rgba(39,31,94,.1)}
.account-form{display:grid;gap:12px}
.account-form label{display:grid;gap:5px;color:var(--ink-soft);font-size:12px;font-weight:600}
.account-form input{width:100%;min-height:44px;padding:10px 12px;border:1px solid rgba(85,69,232,.2);border-radius:10px;background:#fff;font-size:15px}
.account-form input:focus{border-color:var(--earth);outline:2px solid rgba(85,69,232,.12)}
.account-form .primary{width:100%;margin-top:4px}
.auth-message{min-height:20px;margin:10px 0 0;color:#a33e46;font-size:13px}
.signed-in-card{padding:16px;border:1px solid rgba(85,69,232,.13);border-radius:14px;background:#fff}
.signed-in-card p{margin:5px 0;color:var(--ink-soft);font-size:14px}
.account-signout{margin-top:15px;padding:9px 14px;border:1px solid rgba(85,69,232,.2);border-radius:999px;background:#fff;color:var(--earth);font-weight:600;cursor:pointer}
.progress-actions{display:flex;justify-content:flex-end;margin-top:15px}
.chat-history{margin-top:28px}.chat-history-heading{display:flex;align-items:baseline;justify-content:space-between;gap:12px;padding:0 2px 10px;border-bottom:1px solid var(--hairline)}.chat-history-heading h3{margin:0;color:var(--ink);font:500 22px/1.25 var(--display)}.chat-history-heading span{color:var(--ink-faint);font-size:12px}.chat-history-list{display:grid;gap:8px;padding-top:12px}.history-entry{display:flex;width:100%;align-items:center;justify-content:space-between;gap:16px;padding:13px 15px;border:1px solid var(--hairline);border-radius:13px;background:rgba(255,255,255,.035);color:var(--ink);text-align:left;cursor:pointer;transition:transform .2s ease,border-color .2s ease,background .2s ease,box-shadow .2s ease}.history-entry:hover,.history-entry:focus-visible{transform:translateY(-2px);border-color:rgba(168,145,255,.52);background:rgba(168,145,255,.08);box-shadow:0 7px 20px rgba(0,0,0,.12);outline:none}.history-entry strong{overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-weight:500}.history-entry time{flex:none;color:var(--ink-faint);font-size:12px}.history-entry:disabled{cursor:wait;opacity:.65}
.history-entry-copy{display:flex;min-width:0;align-items:center;gap:10px}
.history-kind{flex:none;padding:4px 8px;border:1px solid rgba(176,151,255,.24);border-radius:999px;background:rgba(128,94,255,.1);color:#d8caff;font-size:10px;font-weight:600;letter-spacing:.04em}
.history-quiz-question{margin:18px 0;padding:16px;border:1px solid var(--hairline);border-radius:12px;background:rgba(255,255,255,.025)}
.history-quiz-question h4{margin:0 0 10px;color:var(--ink);font-size:15px}
.history-quiz-question ol{margin:0;padding-left:22px;color:var(--ink-soft);font-size:14px}
.history-quiz-question li{padding:3px 6px;border-radius:6px}
.history-quiz-question li.correct{background:rgba(97,223,202,.12);color:#9af3e4}
.history-quiz-question li.wrong{background:rgba(255,139,157,.12);color:#ffb2c2}
.history-quiz-question p{margin:10px 0 0;color:var(--ink-soft);font-size:13px}
@media(max-width:680px){.chat-history-heading{align-items:flex-start;flex-direction:column;gap:4px}.history-entry{align-items:flex-start;flex-direction:column;gap:5px}}
.clear-progress{padding:8px 13px;border:1px solid rgba(191,70,87,.25);border-radius:999px;background:rgba(255,255,255,.82);color:#a33e46;font-size:12px;font-weight:600;cursor:pointer}
.clear-progress:hover{border-color:#ef6c65;background:#fff0f1}
@keyframes orbit-popup{from{opacity:0;transform:translateY(10px) scale(.94)}to{opacity:1;transform:translateY(0) scale(1)}}
.orbit-node:nth-of-type(2){animation-delay:-1s}
.orbit-node:nth-of-type(3){animation-delay:-2s}
.orbit-node:nth-of-type(4){animation-delay:-3s}

.orbit-card-title{font:600 13px var(--font);letter-spacing:1.2px}
.orbit-card-subtitle{fill:#6b6883;font:400 10px var(--font)}
.orbit-icon{fill:none;stroke:var(--earth);stroke-width:2;stroke-linecap:round;stroke-linejoin:round}
.orbit-spark{fill:var(--accent)}
.idea-glow{fill:url(#ideaGlow)}
.idea-icon{fill:none;stroke:#fff;stroke-width:3;stroke-linecap:round;stroke-linejoin:round}
@keyframes orbit-float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
@media(prefers-reduced-motion:reduce){.orbit-node{animation:none;transition:none}.orbit-dialog[open]{animation:none}}



.tool-card:after{background:linear-gradient(90deg,var(--earth),var(--accent))}
.feedback:not(:empty){margin-top:14px;padding:12px 15px;border-left:3px solid var(--sage);border-radius:0 10px 10px 0;background:rgba(8,127,140,.09);color:#075e68}
.quiz-footer .pill:nth-child(2){border-color:rgba(48,40,95,.28);background:rgba(85,69,232,.08);color:#30285f;font-weight:600}

.toast{border-color:rgba(85,69,232,.24);border-radius:12px;background:#fff;box-shadow:0 14px 35px rgba(63,55,126,.18)}

@media(max-width:900px){.learning-orbit{width:min(580px,86vw)}}
@media(max-width:680px){
  .top .account-button{top:11px;right:12px;padding:7px 10px;font-size:11px}
  .name{margin-right:68px}
  .account-dialog{padding:22px}
  .name-mark,.footer-row .logo{width:30px;height:30px}
  .learning-orbit{width:100%;margin:8px auto 6px}
  .learning-orbit>svg{display:none}
  .learning-orbit-mobile{position:relative;isolation:isolate;display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px 10px}
  .learning-orbit-mobile-constellation{position:absolute;inset:0;z-index:-1;width:100%;height:100%;overflow:visible;pointer-events:none}
  .learning-orbit-mobile-constellation path{fill:none;stroke:rgba(176,151,255,.72);stroke-width:1.5;stroke-dasharray:4 7;vector-effect:non-scaling-stroke;filter:drop-shadow(0 0 4px rgba(168,145,255,.55));animation:constellation-flow 5s linear infinite}
  .learning-orbit-mobile-constellation circle{fill:#61dfca;filter:drop-shadow(0 0 6px rgba(97,223,202,.9));animation:constellation-spark 2.4s ease-in-out infinite}
  .orbit-mobile-node{min-width:0;min-height:92px;padding:14px;border:1px solid rgba(85,69,232,.15);border-radius:15px;background:rgba(255,255,255,.9);box-shadow:0 7px 18px rgba(63,55,126,.07);color:var(--ink);text-align:left;cursor:pointer;transition:box-shadow .2s ease,border-color .2s ease}
  .orbit-mobile-node:hover,.orbit-mobile-node:focus-visible,.orbit-mobile-node[aria-pressed="true"]{border-color:var(--accent);box-shadow:0 10px 24px rgba(85,69,232,.2)}
  .orbit-mobile-node:focus-visible{outline:2px solid var(--earth);outline-offset:3px}
  .orbit-mobile-node strong{display:block;margin-bottom:4px;color:#30285f;font-size:14px}
  .orbit-mobile-node span{display:block;color:var(--ink-soft);font-size:12px;line-height:1.45}
  .orbit-mobile-center{grid-column:1/-1;grid-row:1;min-height:68px;background:linear-gradient(110deg,#5545e8,#9a4bd4 55%,#dd548d);color:#fff;text-align:center}
  .orbit-mobile-center strong,.orbit-mobile-center span{color:#fff}
  }
  @media(max-width:360px){.orbit-mobile-paths{grid-template-columns:repeat(2,minmax(0,1fr));gap:10px 8px}.orbit-mobile-node{min-height:84px;padding:11px}.orbit-mobile-node strong{font-size:13px}.orbit-mobile-node span{font-size:11px}.orbit-mobile-center{grid-column:1/-1}}
@media(max-width:340px){body{min-width:0}}


li:nth-child(4n+1) .plate .n{color:#df7357}
li:nth-child(4n+2) .plate .n{color:#6547ed}
li:nth-child(4n+3) .plate .n{color:#078f88}
li:nth-child(4n) .plate .n{color:#d58a18}
.field input,.field select{border-color:rgba(83,62,166,.2);background:rgba(255,255,255,.92)}

.tool-card .icon{display:grid;width:42px;height:42px;margin-bottom:15px;place-items:center;border-radius:14px;background:linear-gradient(140deg,#ff8a70,#ffbd6e);box-shadow:0 7px 15px rgba(255,107,107,.2);color:#fff;font-size:19px;font-weight:700}
.tool-card:nth-child(2) .icon{background:linear-gradient(140deg,#00a99b,#61d5b8);box-shadow:0 7px 15px rgba(7,143,136,.18)}
.tool-card:after{height:3px}






@media(prefers-reduced-motion:reduce){.tool-card,.style-tab{transition:none}}
.hero h1 em{background:linear-gradient(100deg,#6547ed 8%,#a34be0 52%,#f16d79 96%);background-clip:text;-webkit-background-clip:text;-webkit-text-fill-color:transparent}
.hero-kicker{display:inline-flex;align-items:center;gap:8px;padding:7px 13px;border:1px solid rgba(101,71,237,.15);border-radius:999px;background:linear-gradient(100deg,rgba(255,255,255,.86),rgba(255,239,232,.78));box-shadow:0 5px 16px rgba(83,62,166,.07);color:#7653c8;font-weight:600}
.hero-kicker:before{content:"";width:8px;height:8px;border-radius:50%;background:linear-gradient(135deg,#ff9e62,#ff6b6b);box-shadow:0 0 0 4px rgba(255,107,107,.11)}
.hero-highlights{display:flex;justify-content:center;flex-wrap:wrap;gap:9px;margin:0 18px 4px}
.hero-highlights span{display:inline-flex;align-items:center;gap:7px;padding:7px 12px;border:1px solid rgba(101,71,237,.13);border-radius:999px;background:rgba(255,255,255,.74);box-shadow:0 4px 12px rgba(83,62,166,.055);color:#40385f;font-size:12px;font-weight:600;letter-spacing:.01em}
.hero-highlights span:before{content:"";width:8px;height:8px;border-radius:50%;background:#7653ed;box-shadow:0 0 0 3px rgba(101,71,237,.1)}

.hero-highlights span:nth-child(2):before{background:#12a99c;box-shadow:0 0 0 3px rgba(7,143,136,.1)}

.hero-highlights span:nth-child(3):before{background:#ff806c;box-shadow:0 0 0 3px rgba(255,107,107,.11)}
.learning-orbit{position:relative;isolation:isolate;filter:drop-shadow(0 22px 24px rgba(67,49,150,.1))}
.learning-orbit:before{content:"";position:absolute;z-index:-1;inset:9% 8%;border-radius:50%;background:radial-gradient(ellipse at 25% 32%,rgba(255,173,135,.3),transparent 35%),radial-gradient(ellipse at 74% 36%,rgba(158,139,255,.33),transparent 40%),radial-gradient(ellipse at 50% 75%,rgba(93,218,194,.22),transparent 43%);filter:blur(16px);pointer-events:none}
@media(max-width:680px){.hero-highlights{gap:7px;margin:0 14px 5px}.hero-highlights span{padding:6px 9px;font-size:11px}.hero-kicker{padding:6px 10px}}
.learning-orbit{perspective:1100px;transform-style:preserve-3d}
.learning-orbit svg{transform:rotateX(2deg);transform-style:preserve-3d;transition:transform .45s ease}
.orbit-card-node{transform-style:preserve-3d;transition:filter .2s ease,scale .2s ease,translate .2s ease,rotate .25s ease}
.orbit-card-node:hover,.orbit-card-node:focus-visible{rotate:x 4deg y -4deg}
.idea-node{transform-style:preserve-3d;transition:filter .2s ease,scale .2s ease,rotate .25s ease}
.idea-node:hover,.idea-node:focus-visible{rotate:x -3deg y 3deg}
.hero-highlights span{transition:transform .2s ease,box-shadow .2s ease}
.hero-highlights span:hover{transform:perspective(400px) rotateX(8deg) translateY(-3px);box-shadow:0 9px 18px rgba(83,62,166,.13)}
.hero-kicker,.hero h1,.hero-intro,.hero-highlights,.hint{animation:hero-arrive .65s cubic-bezier(.2,.75,.25,1) both}
.hero h1{animation-delay:.08s}
.hero-intro{animation-delay:.16s}
.hero-highlights{animation-delay:.24s}
.learning-orbit{animation:hero-arrive .75s .2s cubic-bezier(.2,.75,.25,1) both}
.hint{animation-delay:.4s}
.hero h1 em{background-size:200% 100%;animation:headline-shimmer 7s ease-in-out 1s infinite alternate}
.learning-orbit:before{animation:orbit-glow 7s ease-in-out infinite alternate}
.hero-kicker:before{animation:kicker-pulse 2.6s ease-in-out infinite}
@keyframes hero-arrive{from{opacity:0;translate:0 16px}to{opacity:1;translate:0 0}}
@keyframes headline-shimmer{from{background-position:0% 50%}to{background-position:100% 50%}}
@keyframes orbit-glow{from{opacity:.65;transform:scale(.94)}to{opacity:1;transform:scale(1.04)}}
@keyframes kicker-pulse{0%,100%{box-shadow:0 0 0 4px rgba(255,107,107,.11)}50%{box-shadow:0 0 0 7px rgba(255,107,107,.04)}}
@media(max-width:680px){
.orbit-card-node:hover,.orbit-card-node:focus-visible,.idea-node:hover,.idea-node:focus-visible{rotate:none}}
@media(prefers-reduced-motion:reduce){.learning-orbit svg,.orbit-card-node,.idea-node,.hero-highlights span{transition:none!important;transform:none!important;translate:none!important;rotate:none!important}.hero-kicker,.hero h1,.hero-intro,.hero-highlights,.learning-orbit,.hero-idea-prompt,.hint,.hero h1 em,.learning-orbit:before,.hero-kicker:before{animation:none!important;opacity:1}}

.studio-paper,.tool-card,.progress-paper{border-radius:22px;box-shadow:0 14px 36px rgba(70,53,139,.075),inset 0 1px 0 rgba(255,255,255,.8);transition:transform .25s ease,box-shadow .25s ease}
.tool-card:hover{transform:translateY(-3px);box-shadow:0 19px 42px rgba(70,53,139,.12),inset 0 1px 0 rgba(255,255,255,.8)}
.studio-paper:before{border-radius:14px}
.field input,.field select{border-radius:14px;transition:border-color .22s ease,box-shadow .22s ease,background-color .22s ease}

.controls>.primary,.tool-card>.primary{border-radius:14px;box-shadow:0 5px 13px rgba(83,62,166,.16)}
.empty{border-radius:16px;background:rgba(255,255,255,.54)}
.choice{border-radius:13px;transition:border-color .2s ease,background .2s ease,transform .2s ease,box-shadow .2s ease}
.choice:hover:not(:disabled){transform:translateY(-1px);box-shadow:0 5px 13px rgba(70,53,139,.08)}
@media(max-width:680px){.studio-paper,.tool-card,.progress-paper{border-radius:18px}}
@media(prefers-reduced-motion:reduce){.studio-paper,.tool-card,.progress-paper,.choice{transition:none}}
.name{animation:brand-arrive .8s cubic-bezier(.2,.75,.25,1) both}
.name-mark{position:relative;overflow:hidden;transition:transform .25s ease,box-shadow .25s ease}
.name-mark svg{width:23px;height:23px;overflow:visible;filter:drop-shadow(0 1px 1px rgba(45,28,103,.18))}
.name:hover .name-mark{transform:translateY(-2px) rotate(-5deg);box-shadow:0 8px 18px rgba(85,69,232,.3)}
.name:hover{color:#6547ed}
.top nav a{position:relative;transition:color .2s ease,transform .2s ease}
.top nav a:not(.nav-start):after{content:"";position:absolute;right:50%;bottom:-5px;left:50%;height:2px;border-radius:2px;background:linear-gradient(90deg,#6547ed,#ff806c);transition:left .22s ease,right .22s ease}
.top nav a:not(.nav-start):hover:after,.top nav a[aria-current="location"]:after{right:0;left:0}
.top nav a:hover{transform:translateY(-2px)}
.top nav .nav-start{border:1px solid rgba(101,71,237,.17);border-radius:999px;padding:7px 13px;background:rgba(255,255,255,.65);transition:color .2s ease,background .2s ease,transform .2s ease,box-shadow .2s ease}
.top nav .nav-start:hover{transform:translateY(-2px);box-shadow:0 5px 14px rgba(83,62,166,.12)}
.top nav a:nth-child(1){animation:nav-arrive .45s .12s both}
.top nav a:nth-child(2){animation:nav-arrive .45s .18s both}
.top nav a:nth-child(3){animation:nav-arrive .45s .24s both}
.top nav a:nth-child(4){animation:nav-arrive .45s .3s both}
.top nav a:nth-child(5){animation:nav-arrive .45s .36s both}
.top nav a:nth-child(6){animation:nav-arrive .45s .42s both}
.tool-card .output>.result-card,.studio-paper .output>.result-card{transform-origin:50% 0;animation:feedback-arrive .45s cubic-bezier(.2,.75,.25,1) both}
.tool-card .output>.empty:not(:has(.loader)){animation:feedback-arrive .32s ease both}
.quiz-area .quiz-question,.quiz-area .quiz-footer,.quiz-area .choice,.quiz-area .feedback{animation:feedback-arrive .32s ease both}
.quiz-area .choice:nth-of-type(2){animation-delay:.04s}
.quiz-area .choice:nth-of-type(3){animation-delay:.08s}
.quiz-area .choice:nth-of-type(4){animation-delay:.12s}
.quiz-area .feedback:not(:empty){animation:feedback-pop .3s ease both}
.topic-row{animation:feedback-arrive .3s ease both}
.topic-row:nth-child(2){animation-delay:.04s}
.topic-row:nth-child(3){animation-delay:.08s}
.topic-row:nth-child(4){animation-delay:.12s}
.toast.show{animation:toast-pop .28s cubic-bezier(.2,.75,.25,1) both}
@keyframes brand-arrive{from{opacity:0;translate:0 -8px;scale:.97}to{opacity:1;translate:0 0;scale:1}}
@keyframes nav-arrive{from{opacity:0;translate:0 -5px}to{opacity:1;translate:0 0}}
@keyframes feedback-arrive{from{opacity:0;translate:0 10px;scale:.99}to{opacity:1;translate:0 0;scale:1}}
@keyframes feedback-pop{from{opacity:0;scale:.97}to{opacity:1;scale:1}}
@keyframes toast-pop{from{opacity:0;translate:0 10px;scale:.97}to{opacity:1;translate:0 0;scale:1}}
@media(prefers-reduced-motion:reduce){.name,.top nav a,.tool-card .output>.result-card,.studio-paper .output>.result-card,.tool-card .output>.empty,.quiz-area .quiz-question,.quiz-area .quiz-footer,.quiz-area .choice,.quiz-area .feedback,.topic-row,.toast.show{animation:none!important}.top nav a,.name-mark{transition:none!important}}
.clear-progress-dialog{position:fixed;inset:0;width:min(430px,calc(100% - 32px));max-width:none;margin:auto;padding:clamp(22px,5vw,32px);border:1px solid rgba(101,71,237,.2);border-radius:24px;background:linear-gradient(145deg,#fff,#f7f3ff 72%,#fff1eb);box-shadow:0 28px 90px rgba(39,31,94,.28);color:var(--ink)}
.clear-progress-dialog[open]{animation:clear-dialog-in .32s cubic-bezier(.2,.8,.25,1) both}
.clear-progress-dialog::backdrop{background:rgba(25,25,57,.45);backdrop-filter:blur(5px);animation:clear-backdrop-in .25s ease both}
.clear-progress-dialog h2{margin:4px 38px 9px 0;color:#30285f;font:600 25px/1.2 var(--font)}
.clear-progress-dialog p{margin:0;color:var(--ink-soft);font-size:15px;line-height:1.65}
.clear-dialog-icon{display:grid;width:50px;height:50px;margin-bottom:16px;place-items:center;border-radius:17px;background:linear-gradient(140deg,#ffebe8,#ffe2c8);color:#df5965;box-shadow:0 7px 18px rgba(239,108,101,.13)}
.clear-dialog-icon svg{width:24px;height:24px}
.clear-dialog-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:24px}
.clear-dialog-actions button{min-height:42px;padding:9px 16px;border-radius:13px;font-size:14px;font-weight:600;cursor:pointer;transition:transform .18s ease,box-shadow .18s ease,background .18s ease}
.clear-dialog-cancel{border:1px solid rgba(101,71,237,.16);background:#fff;color:var(--ink)}
.clear-dialog-confirm{border:1px solid #df5965;background:linear-gradient(110deg,#ef6c65,#df4c6a);box-shadow:0 6px 15px rgba(223,76,106,.2);color:#fff}
.clear-dialog-actions button:hover{transform:translateY(-2px);box-shadow:0 9px 18px rgba(70,53,139,.16)}
.progress-paper{position:relative;overflow:hidden}
.progress-paper.is-clearing{animation:progress-clear .55s cubic-bezier(.4,0,.7,.3) both;pointer-events:none}
.progress-paper.is-clearing:after{content:"";position:absolute;inset:0;z-index:2;background:linear-gradient(110deg,transparent 15%,rgba(255,255,255,.72) 48%,transparent 80%);animation:clear-sweep .55s ease-in-out both}
.progress-paper.progress-cleared{animation:progress-return .45s cubic-bezier(.2,.75,.25,1) both}
@keyframes clear-dialog-in{from{opacity:0;transform:translateY(14px) scale(.95)}to{opacity:1;transform:translateY(0) scale(1)}}
@keyframes clear-backdrop-in{from{opacity:0}to{opacity:1}}
@keyframes progress-clear{0%{opacity:1;transform:scale(1)}55%{opacity:.55;transform:scale(.985)}100%{opacity:.18;transform:scale(.97)}}
@keyframes progress-return{from{opacity:.55;transform:translateY(8px) scale(.99)}to{opacity:1;transform:translateY(0) scale(1)}}
@keyframes clear-sweep{from{transform:translateX(-110%)}to{transform:translateX(110%)}}
@media(max-width:480px){.clear-dialog-actions{flex-direction:column-reverse}.clear-dialog-actions button{width:100%}}
@media(prefers-reduced-motion:reduce){.clear-progress-dialog[open],.clear-progress-dialog::backdrop,.progress-paper.is-clearing,.progress-paper.is-clearing:after,.progress-paper.progress-cleared{animation:none!important}.clear-dialog-actions button{transition:none}}
.hero-idea-prompt{display:flex;max-width:min(510px,calc(100% - 36px));align-items:center;gap:13px;margin:4px auto 0;padding:13px 18px;border:1px solid rgba(190,164,255,.25);border-radius:18px;background:linear-gradient(115deg,rgba(48,35,86,.88),rgba(42,29,68,.84) 58%,rgba(67,35,72,.78));box-shadow:0 12px 32px rgba(0,0,0,.2),0 0 22px rgba(139,97,255,.12);text-align:left;animation:hero-arrive .65s .32s both}
.hero-idea-icon{display:grid;width:38px;height:38px;flex:0 0 38px;place-items:center;border:1px solid rgba(224,204,255,.2);border-radius:12px;background:linear-gradient(140deg,#7659ed,#d856a8);box-shadow:0 0 18px rgba(168,126,255,.3);color:#fff;font-size:19px}
.hero-idea-prompt strong,.hero-idea-prompt small{display:block}
.hero-idea-prompt strong{color:#fff;font-size:14px}
.hero-idea-prompt small{margin-top:2px;color:var(--ink-soft);font-size:12px;line-height:1.45}
.topic-sparks{display:flex;max-width:610px;align-items:center;justify-content:center;flex-wrap:wrap;gap:8px;margin:13px auto 0;padding:0 16px}
.topic-sparks-label{width:100%;color:var(--ink-faint);font-size:10px;letter-spacing:.12em;text-transform:uppercase}
.topic-spark{padding:6px 11px;border:1px solid rgba(101,71,237,.15);border-radius:999px;background:rgba(255,255,255,.67);color:#554a78;font-size:12px;cursor:pointer;transition:transform .2s ease,border-color .2s ease,background .2s ease,box-shadow .2s ease}
.topic-spark:hover{transform:translateY(-2px);border-color:rgba(101,71,237,.35);background:#fff;box-shadow:0 6px 15px rgba(83,62,166,.1)}
.topic-spark:focus-visible{outline:2px solid var(--earth);outline-offset:3px}
.topic-spark-surprise{border-color:rgba(255,107,107,.23);background:linear-gradient(110deg,rgba(255,255,255,.85),rgba(255,239,232,.8));color:#9b5266;font-weight:600}
.topic-sparks{animation:hero-arrive .65s .44s both}
@media(max-width:680px){.hero-idea-prompt{gap:10px;padding:11px 13px}.hero-idea-prompt strong{font-size:13px}.hero-idea-prompt small{font-size:11px}.topic-sparks{gap:7px;margin-top:10px;padding:0 14px}.topic-spark{padding:6px 9px;font-size:11px}}
@media(prefers-reduced-motion:reduce){.topic-spark{transition:none}.topic-sparks{animation:none}}
body:after{content:"";position:fixed;inset:-20%;z-index:-1;pointer-events:none;background:radial-gradient(ellipse at 18% 24%,rgba(255,126,150,.13),transparent 29%),radial-gradient(ellipse at 82% 28%,rgba(126,103,255,.15),transparent 31%),radial-gradient(ellipse at 55% 83%,rgba(63,208,181,.12),transparent 34%);animation:color-drift 20s ease-in-out infinite alternate}
.primary{border-color:transparent;background:linear-gradient(110deg,#6547ed,#8955e8 52%,#ef718a);background-size:180% 100%;box-shadow:0 7px 18px rgba(101,71,237,.2);transition:background-position .4s ease,box-shadow .25s ease,transform .25s ease}
.primary:hover{border-color:transparent;background-position:100% 50%;box-shadow:0 10px 24px rgba(101,71,237,.28)}
.tool-card,.studio-paper,.progress-paper{transition:transform .3s cubic-bezier(.2,.75,.25,1),box-shadow .3s ease,border-color .3s ease}
.studio-paper:hover,.progress-paper:hover{transform:translateY(-3px);box-shadow:0 20px 46px rgba(70,53,139,.13),inset 0 1px 0 rgba(255,255,255,.85)}
.tool-card{position:relative;overflow:hidden}
.tool-card:after{transform:scaleX(.42);transform-origin:left;transition:transform .35s ease,filter .35s ease}
.tool-card:hover:after{transform:scaleX(1);filter:saturate(1.4)}
.tool-card .icon{transition:transform .3s cubic-bezier(.2,.75,.25,1),box-shadow .3s ease}
.tool-card:hover .icon{transform:translateY(-3px) rotate(-5deg) scale(1.06);box-shadow:0 10px 22px rgba(101,71,237,.22)}

.hero-highlights span:nth-child(2){animation-delay:.35s}
.hero-highlights span:nth-child(3){animation-delay:.7s}
.hero-highlights span{animation:highlight-float 5s ease-in-out infinite}
@keyframes color-drift{from{transform:translate3d(-1%,0,0) scale(1)}to{transform:translate3d(1%,1.5%,0) scale(1.04)}}
@keyframes orbit-dash{to{stroke-dashoffset:-88}}
@keyframes highlight-float{0%,100%{translate:0 0}50%{translate:0 -3px}}
@media(max-width:680px){.studio-paper:hover,.progress-paper:hover{transform:none}.tool-card:hover{transform:translateY(-2px)}}
@media(prefers-reduced-motion:reduce){body:after,.orbit-track,.hero-highlights span{animation:none!important}.primary,.tool-card,.studio-paper,.progress-paper,.tool-card:after,.tool-card .icon{transition:none!important}.studio-paper:hover,.progress-paper:hover,.tool-card:hover,.tool-card:hover .icon{transform:none}}
.learning-orbit{position:relative}
.constellation-sparkles{position:absolute;inset:0;z-index:2;pointer-events:none}
.constellation-sparkles span{position:absolute;color:#8d6aff;font-size:19px;line-height:1;text-shadow:0 3px 12px rgba(101,71,237,.25);animation:constellation-twinkle 3.8s ease-in-out infinite}
.constellation-sparkles span:nth-child(1){top:14%;left:20%;font-size:15px}
.constellation-sparkles span:nth-child(2){top:18%;right:19%;color:#ff806c;animation-delay:-1.1s}
.constellation-sparkles span:nth-child(3){right:24%;bottom:12%;font-size:13px;animation-delay:-2.3s}
.constellation-sparkles span:nth-child(4){bottom:16%;left:22%;color:#12a99c;font-size:16px;animation-delay:-.6s}
@keyframes constellation-twinkle{0%,100%{opacity:.4;translate:0 3px;scale:.8;rotate:-12deg}50%{opacity:1;translate:0 -7px;scale:1.12;rotate:12deg}}
@media(prefers-reduced-motion:reduce){.constellation-sparkles span{animation:none!important;opacity:.8}}
:root{--paper:#100d24;--paper-light:#1b1634;--ink:#f5f0ff;--ink-soft:rgba(239,232,255,.8);--ink-faint:rgba(211,198,240,.62);--hairline:rgba(190,164,255,.2);--earth:#a891ff;--sage:#61dfca;--accent:#ff8b9d}
body{background:#100d24;color:var(--ink)}
body:before{background:radial-gradient(ellipse at 14% 12%,rgba(255,119,161,.12),transparent 36%),radial-gradient(ellipse at 88% 27%,rgba(128,94,255,.2),transparent 39%),radial-gradient(ellipse at 50% 78%,rgba(37,197,176,.09),transparent 42%),linear-gradient(180deg,#100d24,#15102e 58%,#100d24)}
body:after{background:radial-gradient(ellipse at 18% 24%,rgba(255,89,157,.11),transparent 29%),radial-gradient(ellipse at 82% 28%,rgba(126,103,255,.16),transparent 31%),radial-gradient(ellipse at 55% 83%,rgba(63,208,181,.1),transparent 34%)}
.top:before{background:linear-gradient(180deg,rgba(16,13,36,.97),rgba(16,13,36,.89) 56%,rgba(16,13,36,0))}
.top nav a,.top nav a:hover,.top nav a[aria-current="location"]{color:var(--ink-soft)}
.top nav .nav-start{position:relative;overflow:hidden;padding:9px 17px;border:1px solid rgba(213,194,255,.52);background:linear-gradient(110deg,#7051e8,#a74bdf 54%,#e85693);background-size:200% 100%;box-shadow:0 7px 22px rgba(130,82,234,.32);color:#fff;font-weight:700;animation:nav-cta-glow 3.5s ease-in-out infinite}
.top nav .nav-start:hover{background-position:100% 50%;box-shadow:0 9px 28px rgba(210,80,171,.38);color:#fff}
.top .account-button{overflow:hidden;border-color:rgba(255,177,206,.55);background:linear-gradient(120deg,#ff9a78,#f05b9a 54%,#ae55e7);background-size:180% 100%;box-shadow:0 7px 22px rgba(237,82,159,.28);color:#fff;font-weight:700;transition:background-position .35s ease,box-shadow .25s ease,transform .25s ease}
.top .account-button:hover{transform:translateY(-2px);border-color:#ffd1df;background-position:100% 50%;box-shadow:0 10px 28px rgba(237,82,159,.42);color:#fff}
@keyframes nav-cta-glow{0%,100%{box-shadow:0 7px 22px rgba(130,82,234,.27)}50%{box-shadow:0 8px 28px rgba(223,83,174,.42)}}
.orbit-track{stroke-dasharray:2 8;animation:orbit-dash 18s linear infinite}
.orbit-link{stroke-dasharray:5 8;animation:constellation-flow 5s linear infinite}
.orbit-spark{filter:drop-shadow(0 0 4px #ffb2db);transform-box:fill-box;transform-origin:center;animation:constellation-spark 2.4s ease-in-out infinite}
.orbit-spark:nth-of-type(2){animation-delay:-1.2s}
.idea-ripple{fill:none;stroke:rgba(196,170,255,.6);stroke-width:2;transform-box:fill-box;transform-origin:center;animation:idea-ripple 3s ease-out infinite}
.idea-ripple.ripple-two{animation-delay:1.5s}
.idea-glow{filter:drop-shadow(0 0 15px rgba(159,119,255,.4));animation:idea-breathe 3.2s ease-in-out infinite}
.orbit-node{animation-duration:5.5s}
.orbit-card-node:hover .orbit-card,.orbit-card-node:focus-visible .orbit-card,.orbit-card-node[aria-pressed="true"] .orbit-card{fill:#392961;stroke:#ff9cbb;filter:drop-shadow(0 0 8px rgba(255,126,185,.22))}
.orbit-card-node:hover .orbit-card-title,.orbit-card-node:focus-visible .orbit-card-title,.orbit-card-node[aria-pressed="true"] .orbit-card-title{fill:#fff}
.orbit-revision-node .orbit-card{stroke:rgba(97,223,202,.62)}
.orbit-revision-node .orbit-card-title{fill:#9af3e4}
.orbit-revision-node:hover .orbit-card,.orbit-revision-node:focus-visible .orbit-card,.orbit-revision-node[aria-pressed="true"] .orbit-card{fill:#193b3b;stroke:#61dfca;filter:drop-shadow(0 0 12px rgba(97,223,202,.38))}
.orbit-revision-node:hover .orbit-card-title,.orbit-revision-node:focus-visible .orbit-card-title,.orbit-revision-node[aria-pressed="true"] .orbit-card-title{fill:#fff}
.orbit-revision-link{stroke:#61dfca;stroke-width:2;filter:drop-shadow(0 0 5px rgba(97,223,202,.55))}
.orbit-card{stroke-dasharray:3 5;animation:revision-orbit-dash 7s linear infinite}
.orbit-core-outline{stroke-dasharray:3 5;animation:revision-orbit-dash 7s linear infinite}
.orbit-mobile-node{border-style:dashed;animation:revision-mobile-outline 7s ease-in-out infinite}
.orbit-mobile-node:nth-child(2){animation-delay:-1.4s}
.orbit-mobile-node:nth-child(3){animation-delay:-2.8s}
.orbit-mobile-node:nth-child(4){animation-delay:-4.2s}
.orbit-mobile-node:nth-child(5){animation-delay:-5.6s}
@keyframes revision-mobile-outline{0%,100%{outline:1px dashed rgba(97,223,202,.35);outline-offset:2px}50%{outline:1px dashed rgba(176,151,255,.78);outline-offset:5px}}

.orbit-mobile-node{transition:transform .25s ease,box-shadow .25s ease,border-color .25s ease}
.orbit-mobile-revision{border-color:rgba(97,223,202,.42);background:linear-gradient(145deg,rgba(23,65,68,.92),rgba(28,23,52,.98))}
.orbit-mobile-revision strong{color:#9af3e4!important}
.orbit-mobile-node:hover,.orbit-mobile-node:focus-visible,.orbit-mobile-node[aria-pressed="true"]{transform:translateY(-3px);border-color:#ff9cbb;box-shadow:0 12px 28px rgba(149,92,230,.24),0 0 18px rgba(255,139,187,.12)}
@keyframes constellation-flow{to{stroke-dashoffset:-52}}
@keyframes constellation-spark{0%,100%{opacity:.55;scale:.8}50%{opacity:1;scale:1.75}}
@keyframes idea-ripple{0%{opacity:.8;scale:.84}100%{opacity:0;scale:1.55}}
@keyframes idea-breathe{0%,100%{opacity:.92}50%{opacity:1}}
@media(prefers-reduced-motion:reduce){.top nav .nav-start,.top .account-button,.orbit-track,.orbit-link,.orbit-spark,.idea-ripple,.idea-glow{animation:none!important}.top nav .nav-start,.top .account-button,.orbit-mobile-node{transition:none!important}}
.hero{background:radial-gradient(ellipse at 50% 42%,rgba(76,52,145,.22),transparent 62%)}
.hero-kicker{align-self:center;border-color:rgba(181,151,255,.3);background:linear-gradient(110deg,rgba(66,43,111,.76),rgba(76,37,81,.76));box-shadow:0 0 28px rgba(134,91,255,.14);color:#e3d5ff;animation:kicker-life 4s ease-in-out infinite}
.hero-kicker:before{background:linear-gradient(135deg,#ffe27b,#ff769e);box-shadow:0 0 13px rgba(255,118,158,.68)}
.hero h1 em{background-image:linear-gradient(100deg,#b6a0ff 5%,#ff91bd 53%,#73ead6 96%)}
.hero-intro,.hint{color:var(--ink-soft)}
.hero-highlights span{border-color:rgba(178,152,255,.25);background:rgba(34,27,62,.88);color:#f1eaff}
.hero-highlights span:nth-child(2){border-color:rgba(97,223,202,.3)}
.hero-highlights span:nth-child(3){border-color:rgba(255,139,157,.3)}
.field input::placeholder{color:rgba(211,198,240,.55)}
.primary{color:#fff;background:linear-gradient(110deg,#7758ed,#a04fe0 55%,#e85891);box-shadow:0 8px 24px rgba(119,88,237,.26)}
.primary:hover{background:linear-gradient(110deg,#8c70ff,#b25bed 55%,#f16b9b);box-shadow:0 11px 28px rgba(148,92,237,.36)}

.about-mark{opacity:.8}
.section-label{color:#c4aaff}
.section-title{color:#f5f0ff}
.section-copy{color:var(--ink-soft)}
.plate{border-color:var(--hairline)}
.plate:hover{background:rgba(129,99,203,.12)}
.plate .n,.plate .p{color:var(--ink-faint)}
.plate .t{color:#f5f0ff}
.studio-paper{border-color:rgba(180,153,255,.24);background:linear-gradient(135deg,rgba(37,29,67,.97),rgba(30,25,55,.96) 58%,rgba(58,32,69,.88));box-shadow:0 18px 48px rgba(0,0,0,.2),inset 0 1px 0 rgba(255,255,255,.06)}

.field label,.style-tab{color:var(--ink-soft)}
.field input,.field select,.account-form input{border-color:rgba(190,164,255,.24);background:#17132d;color:var(--ink)}
.field input:focus,.field select:focus{border-color:#a891ff;background:#1c1737;box-shadow:0 0 0 3px rgba(168,145,255,.16)}
.field select option{background:#17132d;color:var(--ink)}
.style-tab:hover,.style-tab.active{border-color:rgba(176,151,255,.38);background:rgba(128,94,255,.17);color:#ded2ff}
.empty{border-color:rgba(190,164,255,.25);background:rgba(18,14,38,.55);color:var(--ink-soft)}
.result-card{border-left-color:#ff8b9d;background:linear-gradient(120deg,rgba(38,29,68,.95),rgba(29,25,55,.96))}
.result-card h3,.result-card p,.notes-list,.takeaways div,.diagram,.feedback,.output>.empty{color:var(--ink)}
.result-card h4{color:#71e3d1}
.takeaways div:nth-child(3n+1){border-color:rgba(176,151,255,.3);background:rgba(128,94,255,.12)}
.takeaways div:nth-child(3n+2){border-color:rgba(97,223,202,.3);background:rgba(30,151,139,.12)}
.takeaways div:nth-child(3n){border-color:rgba(255,139,157,.32);background:rgba(199,77,112,.12)}
.diagram{border-color:rgba(190,164,255,.22);background:rgba(16,13,36,.55);color:#83ead8}
.tool-card{border-color:rgba(190,164,255,.2);background:linear-gradient(145deg,rgba(37,29,67,.98),rgba(27,23,51,.97));box-shadow:0 14px 35px rgba(0,0,0,.2)}
.tool-card:nth-child(1){border-color:rgba(255,139,157,.3);background:linear-gradient(145deg,rgba(68,35,68,.8),rgba(28,23,52,.98) 70%)}
.tool-card:nth-child(2){border-color:rgba(97,223,202,.3);background:linear-gradient(145deg,rgba(23,65,68,.72),rgba(28,23,52,.98) 70%)}
.tool-card h3,.tool-card .subtle{color:#f2edff}
.notes-list{color:var(--ink-soft)}
.pill{border-color:rgba(190,164,255,.25);color:var(--ink-faint)}
.quiz-footer .pill:nth-child(2){border-color:rgba(176,151,255,.3);background:rgba(128,94,255,.16);color:#e5dbff}
.choice{border-color:rgba(190,164,255,.22);background:rgba(17,14,37,.7);color:#f1ebff}
.choice:hover:not(:disabled){border-color:#b49aff;background:rgba(90,65,150,.28)}
.choice.correct{border-color:#61dfca;background:rgba(35,170,151,.18);color:#9af3e4}
.choice.wrong{border-color:#ff8b9d;background:rgba(220,80,119,.17);color:#ffb2c2}
.feedback:not(:empty){border-color:#61dfca;background:rgba(33,143,132,.16);color:#a5f3e7}
.progress-paper{border-color:rgba(190,164,255,.2);background:linear-gradient(135deg,rgba(34,27,62,.92),rgba(22,28,56,.94))}
.metric:nth-child(1) strong{color:#b49aff}
.metric:nth-child(2) strong{color:#61dfca}
.metric:nth-child(3) strong{color:#ff91ad}
.metric span,.topic-row,.topic-row span:last-child{color:var(--ink-faint)}
.topic-list,.topic-row{border-color:var(--hairline)}
footer{border-color:var(--hairline)}
.foot-links,.fine{color:var(--ink-faint)}
.footer-row .brand{color:#f5f0ff}
.footer-row .logo{border:0;border-radius:10px;background:linear-gradient(140deg,#7758ed,#e85891);color:#fff}
.toast{border-color:rgba(190,164,255,.28);background:#211a3c;color:#f5f0ff}


.orbit-card{fill:#251d43;stroke:rgba(190,164,255,.34)}


.learning-orbit:before{background:radial-gradient(ellipse at 25% 32%,rgba(255,117,165,.25),transparent 35%),radial-gradient(ellipse at 74% 36%,rgba(138,107,255,.35),transparent 40%),radial-gradient(ellipse at 50% 75%,rgba(61,214,187,.22),transparent 43%)}
.orbit-mobile-node{border-color:rgba(190,164,255,.24);background:linear-gradient(145deg,#251d43,#1b1733);color:#f5f0ff}
.orbit-mobile-node strong{color:#e5d8ff}
.orbit-mobile-node span{color:var(--ink-soft)}
.orbit-mobile-center{background:linear-gradient(115deg,#6748df,#9a4bd4 55%,#dd548d)}
.orbit-dialog,.account-dialog,.clear-progress-dialog{border-color:rgba(190,164,255,.28);background:linear-gradient(145deg,#251d43,#19142f 78%,#32203f);color:var(--ink)}
.orbit-dialog h2,.account-dialog h2,.clear-progress-dialog h2{color:#f2eaff}
.account-dialog .account-intro,.account-form label,.signed-in-card p{color:var(--ink-soft)}
.account-tabs{background:#17132d}
.account-tabs button{color:var(--ink-soft)}
.account-tabs button[aria-pressed="true"]{background:#302451;color:#e5d8ff}
.account-form input{border-color:rgba(190,164,255,.24);background:#17132d;color:var(--ink)}
.account-form input:focus{border-color:#a891ff;outline-color:rgba(168,145,255,.2)}
.signed-in-card{border-color:rgba(190,164,255,.2);background:#1b1634;color:var(--ink)}
.account-signout,.clear-dialog-cancel{border-color:rgba(190,164,255,.25);background:#211a3c;color:#eee5ff}
.orbit-dialog-close{border-color:rgba(190,164,255,.25);background:#211a3c;color:#e5d8ff}
.orbit-dialog-close:hover{background:#342658}
.auth-message{color:#ff9daf}
.hero:before,.hero:after{opacity:.55;filter:hue-rotate(210deg) saturate(1.5)}
.topic-spark{border-color:rgba(190,164,255,.24);background:rgba(38,30,68,.88);color:#e6dcff}
.topic-spark:hover{border-color:#b49aff;background:#302451}
.topic-spark-surprise{border-color:rgba(255,139,157,.35);background:linear-gradient(110deg,rgba(73,45,99,.92),rgba(97,40,77,.85));color:#ffc3d1}
.about-mark{filter:hue-rotate(185deg) saturate(1.5) brightness(1.5)}
.hero-kicker{line-height:1.35;text-align:center}
@keyframes kicker-life{0%,100%{box-shadow:0 0 18px rgba(134,91,255,.12)}50%{box-shadow:0 0 30px rgba(255,111,169,.27)}}
.hero:before{animation:hero-branch 7s ease-in-out infinite alternate}
.hero:after{animation:hero-branch 8s ease-in-out -2s infinite alternate}
@keyframes hero-branch{from{translate:0 0}to{translate:0 -9px}}
.reveal.visible .section-label{animation:section-label-in .55s cubic-bezier(.2,.75,.25,1) both}
@keyframes section-label-in{from{opacity:0;translate:0 8px;letter-spacing:.28em}to{opacity:1;translate:0 0;letter-spacing:var(--caps)}}
@media(max-width:680px){.hero:before,.hero:after{opacity:.2}.hero:after{animation:none}}
@media(max-width:680px){.constellation-sparkles{display:none}}
@media(prefers-reduced-motion:reduce){.hero-kicker,.hero:before,.hero:after,.reveal.visible .section-label{animation:none!important}.hero:before,.hero:after{translate:none}}
.rule:before{background:linear-gradient(90deg,transparent 0%,rgba(175,148,255,.32) 18%,rgba(175,148,255,.32) 46%,transparent 48%,transparent 52%,rgba(175,148,255,.32) 54%,rgba(175,148,255,.32) 82%,transparent 100%)}
.rule:after{content:"";width:11px;height:11px;padding:0;border:2px solid #17112c;border-radius:3px;background:linear-gradient(135deg,#b49aff,#ff84ad);box-shadow:0 0 0 1px rgba(191,165,255,.35),0 0 17px rgba(173,123,255,.6);transform:translate(-50%,-50%) rotate(45deg)}
.studio-paper{isolation:isolate;overflow:hidden;box-shadow:0 18px 48px rgba(0,0,0,.2),0 0 28px rgba(130,91,255,.1),inset 0 1px 0 rgba(255,255,255,.06)}
.studio-paper:before{z-index:0}
.studio-paper:after{content:"";position:absolute;inset:1px;z-index:0;border-radius:inherit;background:linear-gradient(112deg,transparent 24%,rgba(183,158,255,.035) 36%,rgba(183,158,255,.13) 46%,rgba(255,146,190,.1) 51%,rgba(97,223,202,.055) 57%,transparent 70%);background-size:230% 100%;animation:desk-light-sweep 9s ease-in-out infinite;pointer-events:none}
.studio-paper>*{z-index:1}
.studio-paper:hover{box-shadow:0 22px 54px rgba(0,0,0,.28),0 0 38px rgba(140,102,255,.2),inset 0 1px 0 rgba(255,255,255,.08)}
.studio-paper:focus-within{border-color:rgba(231,214,255,.72);box-shadow:0 22px 58px rgba(0,0,0,.3),0 0 0 1px rgba(190,164,255,.2),0 0 42px rgba(140,102,255,.27),inset 0 1px 0 rgba(255,255,255,.1)}
.studio-paper:hover:after,.studio-paper:focus-within:after{animation-duration:3.6s;opacity:1}
.studio-paper:hover .desk-sparkles span,.studio-paper:focus-within .desk-sparkles span{animation-duration:1.15s;text-shadow:0 0 5px #fff,0 0 14px rgba(203,175,255,1),0 0 28px rgba(166,111,255,.95)}
.studio-paper .field:focus-within label{color:#e3d5ff;text-shadow:0 0 13px rgba(168,145,255,.45)}
.studio-paper .field input,.studio-paper .field select{transition:border-color .22s ease,box-shadow .22s ease,background .22s ease,transform .22s ease}
.studio-paper .field input:focus,.studio-paper .field select:focus{transform:translateY(-1px);box-shadow:0 0 0 3px rgba(168,145,255,.2),0 5px 18px rgba(0,0,0,.18)}
.studio-paper .style-tab{border-radius:10px;transition:color .2s ease,border-color .2s ease,background .2s ease,transform .2s ease,box-shadow .2s ease}
.studio-paper .style-tab:hover{transform:translateY(-2px);box-shadow:0 5px 16px rgba(133,96,226,.17)}
.studio-paper .style-tab.active{box-shadow:0 0 18px rgba(133,96,226,.14),inset 0 1px 0 rgba(255,255,255,.06)}
@keyframes desk-light-sweep{0%,12%{background-position:120% 50%;opacity:.45}58%,100%{background-position:-20% 50%;opacity:1}}
@media(prefers-reduced-motion:reduce){.studio-paper:after{animation:none;background-position:50% 50%;opacity:.45}.studio-paper:hover,.studio-paper .field input:focus,.studio-paper .field select:focus,.studio-paper .style-tab:hover{transform:none}.studio-paper .field input,.studio-paper .field select,.studio-paper .style-tab{transition:none}}
.desk-sparkles{position:absolute!important;inset:0;z-index:2!important;overflow:hidden;border-radius:inherit;pointer-events:none}
.desk-sparkles span{position:absolute;color:#e7d9ff;font-size:18px;line-height:1;text-shadow:0 0 8px rgba(203,175,255,.95),0 0 20px rgba(166,111,255,.7);animation:desk-sparkle 3.6s ease-in-out infinite}
.desk-sparkles span:nth-child(1){top:9%;right:8%;font-size:17px}
.desk-sparkles span:nth-child(2){top:32%;right:3%;color:#ffb2d1;font-size:12px;animation-delay:-1.2s}
.desk-sparkles span:nth-child(3){right:13%;bottom:8%;color:#9df2e0;font-size:14px;animation-delay:-2.4s}
.section-title:after{content:"";display:block;width:40px;height:3px;margin-top:14px;border-radius:999px;background:linear-gradient(90deg,#a891ff,#ff8b9d,#61dfca);box-shadow:0 0 13px rgba(168,145,255,.3);transform-origin:left;animation:title-glint 3s ease-in-out infinite}
@keyframes desk-sparkle{0%,100%{opacity:.22;scale:.6;rotate:-18deg}50%{opacity:1;scale:1.2;rotate:18deg}}
@keyframes title-glint{0%,100%{scale:.78 1;filter:saturate(.85)}50%{scale:1.18 1;filter:saturate(1.5)}}
@media(prefers-reduced-motion:reduce){.desk-sparkles span,.section-title:after{animation:none!important}.desk-sparkles span{opacity:.75}}
.learning-orbit{filter:drop-shadow(0 12px 14px rgba(4,2,20,.3))}
.learning-orbit svg{transform:none;filter:drop-shadow(0 1px 0 rgba(241,232,255,.12));backface-visibility:hidden}
.orbit-link{stroke:rgba(211,193,255,.62);stroke-width:2;filter:drop-shadow(0 0 1px rgba(194,168,255,.45))}
.orbit-track{stroke:rgba(202,181,255,.56);stroke-width:2}
.orbit-track{transform-box:view-box;transform-origin:380px 170px;animation:orbit-dash 18s linear infinite,constellation-orbit-spin 52s linear infinite}
.orbiting-satellites{transform-box:view-box;transform-origin:380px 170px;animation:constellation-orbit-spin 26s linear infinite}
.orbiting-satellites circle{fill:#61dfca;filter:drop-shadow(0 0 5px rgba(97,223,202,.9))}
@keyframes constellation-orbit-spin{to{transform:rotate(360deg)}}
.orbit-card{stroke:rgba(211,193,255,.58);stroke-width:1.5}
.orbit-card-title{fill:#fff;font-weight:700}
.orbit-card-subtitle{fill:#e2d8f7}
.orbit-spark{filter:drop-shadow(0 0 1px #fff);stroke:#ffe5f2;stroke-width:1}
.orbit-card-node:hover .orbit-card,.orbit-card-node:focus-visible .orbit-card,.orbit-card-node[aria-pressed="true"] .orbit-card{filter:drop-shadow(0 2px 3px rgba(255,126,185,.28))}
.idea-glow{filter:drop-shadow(0 0 5px rgba(159,119,255,.5))}
.idea-node:hover .idea-glow,.idea-node:focus-visible .idea-glow,.idea-node[aria-pressed="true"] .idea-glow{filter:drop-shadow(0 0 8px rgba(255,119,184,.72))}
.constellation-sparkles span{ text-shadow:0 0 2px rgba(255,255,255,.9),0 0 5px rgba(166,111,255,.48)}
.studio-paper{border-color:rgba(205,183,255,.38);box-shadow:0 18px 48px rgba(0,0,0,.2),0 0 22px rgba(130,91,255,.08),inset 0 1px 0 rgba(255,255,255,.09)}
.studio-paper:before{border-color:rgba(213,194,255,.2)}
.studio-paper:after{background:linear-gradient(112deg,transparent 24%,rgba(183,158,255,.025) 36%,rgba(183,158,255,.09) 46%,rgba(255,146,190,.07) 51%,rgba(97,223,202,.035) 57%,transparent 70%)}
@media(max-width:680px){.learning-orbit svg{transform:none}}
@media(prefers-reduced-motion:reduce){.learning-orbit svg{transform:none!important}}
.topic-row{align-items:center;flex-wrap:wrap}
.topic-history-bar{width:100%;height:7px;overflow:hidden;border-radius:999px;background:rgba(190,164,255,.14)}
.topic-history-bar span{display:block;height:100%;border-radius:inherit;background:linear-gradient(90deg,#7758ed,#ff8b9d,#61dfca);transition:width .45s ease}
.topic-history-bar[role="progressbar"]{outline-offset:3px}
@media(prefers-reduced-motion:reduce){.topic-history-bar span{transition:none}}
.revision{max-width:var(--content);margin:0 auto;padding:0 clamp(22px,5vw,52px)}
.revision-layout{display:grid;grid-template-columns:minmax(0,1.35fr) minmax(250px,.65fr);gap:20px;margin-top:24px}
.revision-panel{min-width:0;padding:clamp(20px,3.5vw,34px);border:1px solid rgba(190,164,255,.22);border-radius:22px;background:linear-gradient(145deg,rgba(37,29,67,.96),rgba(27,23,51,.96));box-shadow:0 16px 38px rgba(0,0,0,.17);transition:transform .25s ease,box-shadow .25s ease}
.revision-panel:hover{transform:translateY(-3px);box-shadow:0 20px 44px rgba(0,0,0,.24),0 0 26px rgba(130,91,255,.1)}
.revision-panel-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}
.revision-panel-heading h3{margin:0;color:var(--ink);font:400 25px/1.2 var(--display)}
.revision-panel-heading .pill{white-space:nowrap}
.revision-flashcard{display:block;width:100%;min-height:220px;padding:0;border:0;border-radius:18px;background:transparent;text-align:left;cursor:pointer;perspective:1000px}
.revision-flashcard:focus-visible{outline:2px solid var(--earth);outline-offset:5px}
.revision-card-inner{position:relative;display:grid;min-height:220px;transform-style:preserve-3d;transition:transform .55s cubic-bezier(.2,.75,.25,1)}
.revision-flashcard.is-flipped .revision-card-inner{transform:rotateY(180deg)}
.revision-card-face{position:absolute;inset:0;display:flex;flex-direction:column;align-items:flex-start;justify-content:center;gap:12px;padding:clamp(20px,4vw,34px);border:1px solid rgba(190,164,255,.24);border-radius:18px;background:radial-gradient(ellipse at 88% 5%,rgba(126,94,255,.18),transparent 42%),linear-gradient(140deg,#201a3d,#17132d);backface-visibility:hidden}
.revision-card-face.back{transform:rotateY(180deg);border-color:rgba(97,223,202,.3);background:radial-gradient(ellipse at 90% 8%,rgba(38,176,155,.15),transparent 44%),linear-gradient(140deg,#1b2c38,#17132d)}
.revision-card-face strong{color:#f5f0ff;font:400 clamp(20px,2.5vw,27px)/1.35 var(--display)}
.revision-card-face p{margin:0;color:var(--ink-soft);font-size:14px}
.revision-card-face .section-label{color:#b49aff}
.revision-card-face.back .section-label{color:var(--sage)}
.revision-card-hint{color:var(--ink-faint);font-size:12px}
.revision-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:14px}
.revision-actions button{min-width:116px}
.revision-again{border:1px solid rgba(255,139,157,.38);background:rgba(220,80,119,.12);color:#ffb2c2}
.revision-again:hover{background:rgba(220,80,119,.23)}
.revision-got-it{border-color:rgba(97,223,202,.5);background:linear-gradient(110deg,#159a8b,#38c9aa);color:#fff}
.revision-session-progress{margin:14px 0;color:var(--ink-faint);font-size:12px}
.revision-meter{height:7px;overflow:hidden;border-radius:999px;background:rgba(190,164,255,.13)}
.revision-meter span{display:block;height:100%;border-radius:inherit;background:linear-gradient(90deg,#7758ed,#ff8b9d,#61dfca);transition:width .35s ease}
.revision-stat{display:flex;align-items:baseline;gap:9px;margin:0 0 5px}
.revision-stat strong{color:#b49aff;font:400 48px/1 var(--display)}
.revision-stat span,.revision-caption{color:var(--ink-soft);font-size:13px}
.weak-topic-list{display:grid;gap:10px;margin-top:21px}
.weak-topic{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:3px 12px;width:100%;padding:12px 14px;border:1px solid rgba(190,164,255,.18);border-radius:14px;background:rgba(17,14,37,.55);color:var(--ink);text-align:left;cursor:pointer;transition:transform .2s ease,border-color .2s ease,background .2s ease}
.weak-topic:hover{transform:translateX(3px);border-color:rgba(255,139,157,.52);background:rgba(90,65,150,.2)}
.weak-topic strong{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.weak-topic span{color:#ffb2c2;font-size:12px;font-variant-numeric:tabular-nums}
.weak-topic small{grid-column:1/-1;color:var(--ink-faint);font-size:11px}
.revision-complete{padding:27px 20px;border:1px dashed rgba(190,164,255,.24);border-radius:16px;background:rgba(17,14,37,.38);text-align:center}
.revision-complete strong{display:block;margin-bottom:7px;color:#9af3e4;font:400 25px/1.2 var(--display)}
.revision-complete p{margin:0;color:var(--ink-soft);font-size:14px}
.plate-revision .n{color:#61dfca!important}
.plate-revision:hover{border-color:rgba(97,223,202,.38);background:rgba(30,151,139,.1)}
.plate-revision:hover .p{color:#9af3e4}
.plate-concept-map .n{color:#b49aff!important}
.plate-concept-map:hover{border-color:rgba(176,151,255,.42);background:rgba(128,94,255,.1)}
.plate-concept-map:hover .p{color:#c4aaff}
.orbit-revision-link{stroke-dasharray:4 6;animation-duration:2.2s}
.orbit-revision-node .orbit-card{stroke-dasharray:3 5;animation:revision-orbit-dash 7s linear infinite}
@keyframes revision-orbit-dash{to{stroke-dashoffset:-32}}
@media(max-width:760px){.revision-layout{grid-template-columns:1fr}.revision-panel:hover{transform:none}}
@media(max-width:480px){.revision-actions{display:grid;grid-template-columns:1fr 1fr}.revision-actions button{min-width:0}.revision-flashcard,.revision-card-inner{min-height:245px}}
@media(prefers-reduced-motion:reduce){.revision-panel,.revision-panel:hover,.revision-flashcard,.revision-card-inner,.revision-meter span,.weak-topic{transition:none!important}.revision-panel:hover,.weak-topic:hover{transform:none}.orbit-card,.orbit-core-outline,.orbit-mobile-node{animation:none!important}.orbit-mobile-node{outline:none}}
.concept-map{max-width:var(--content);margin:0 auto;padding:0 clamp(22px,5vw,52px)}
.concept-map-paper{position:relative;isolation:isolate;overflow:hidden;margin-top:24px;padding:clamp(20px,4vw,38px);border:1px solid rgba(190,164,255,.28);border-radius:22px;background:linear-gradient(145deg,rgba(37,29,67,.96),rgba(20,23,51,.97));box-shadow:0 18px 46px rgba(0,0,0,.2),inset 0 1px 0 rgba(255,255,255,.06);transition:border-color .25s ease,box-shadow .25s ease}
.concept-map-paper:before{content:"";position:absolute;inset:10px;z-index:0;border:1px dashed rgba(190,164,255,.18);border-radius:16px;pointer-events:none}
.concept-map-paper>*{position:relative;z-index:1}
.concept-map-paper:focus-within,.concept-map-paper:hover{border-color:rgba(97,223,202,.5);box-shadow:0 22px 52px rgba(0,0,0,.28),0 0 32px rgba(97,223,202,.09)}
.concept-map-controls{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:end;gap:13px}
.concept-map-controls .field input{border-radius:13px}
.concept-map-controls .primary{min-height:46px;border-radius:13px}
.concept-map-hint{margin:12px 0 0;color:var(--ink-faint);font-size:12px}
.concept-map-output{margin-top:18px}
.concept-map-canvas{position:relative;min-height:clamp(340px,55vw,520px);overflow:hidden;border:1px solid rgba(190,164,255,.18);border-radius:18px;background:radial-gradient(ellipse at 50% 48%,rgba(104,77,193,.16),transparent 52%),rgba(15,13,34,.52)}
.concept-map-orbit{position:absolute;inset:9% 15%;border:1px dashed rgba(97,223,202,.31);border-radius:50%;pointer-events:none;animation:concept-orbit-spin 32s linear infinite}
.concept-map-orbit:before,.concept-map-orbit:after{content:"";position:absolute;width:9px;height:9px;border:2px solid #61dfca;border-radius:50%;background:#191830;box-shadow:0 0 14px rgba(97,223,202,.78)}
.concept-map-orbit:before{top:-5px;left:50%}
.concept-map-orbit:after{right:8%;bottom:13%;width:6px;height:6px;border-color:#ff8b9d;box-shadow:0 0 12px rgba(255,139,157,.72)}
.concept-map-svg{position:absolute;inset:0;width:100%;height:100%;overflow:visible}
.concept-map-orbit{z-index:1}
.concept-map-svg{z-index:2}
.concept-map-edge{stroke:rgba(176,151,255,.35);stroke-width:1.5;stroke-dasharray:4 7;animation:concept-edge-flow 8s linear infinite}
.concept-map-node{cursor:pointer;outline:none;animation:concept-node-arrive .45s cubic-bezier(.2,.75,.25,1) both}
.concept-map-node circle{fill:#211a3e;stroke:rgba(176,151,255,.7);stroke-width:1.5;transition:fill .2s ease,stroke .2s ease,filter .2s ease,stroke-width .2s ease;animation:concept-node-pulse 4.5s ease-in-out infinite}
.concept-map-node:nth-of-type(2n) circle{animation-delay:-2.25s}
.concept-map-node text{fill:#f5f0ff;font:600 13px var(--font);pointer-events:none}
.concept-map-node:hover circle,.concept-map-node:focus-visible circle,.concept-map-node[aria-pressed="true"] circle{fill:#193b3b;stroke:#61dfca;stroke-width:2.5;filter:drop-shadow(0 0 11px rgba(97,223,202,.56))}
.concept-map-node:focus-visible circle{stroke-width:3.5}
.concept-map-center circle{fill:#352653;stroke:#ff8b9d;stroke-width:2}
.concept-map-center:hover circle,.concept-map-center:focus-visible circle{fill:#4b2c58;stroke:#ffb0c7}
.concept-map-center text{font-size:14px;font-weight:700}
.concept-map-edge.is-related{stroke:#61dfca;stroke-width:2.5;filter:drop-shadow(0 0 7px rgba(97,223,202,.8));animation-duration:2.6s}
.concept-map-details{min-height:90px;margin-top:14px;padding:17px 19px;border-left:2px solid #61dfca;border-radius:0 13px 13px 0;background:rgba(97,223,202,.08);animation:feedback-arrive .3s ease both}
.concept-map-details h3{margin:0 0 5px;color:#9af3e4;font:400 22px/1.2 var(--display)}
.concept-map-details p{margin:0;color:var(--ink-soft);font-size:14px}
.concept-map-details button{margin-top:12px;padding:7px 12px;border:1px solid rgba(97,223,202,.4);border-radius:999px;background:rgba(97,223,202,.1);color:#9af3e4;font-size:12px;cursor:pointer;transition:background .2s ease,transform .2s ease}
.concept-map-details button:hover{transform:translateY(-2px);background:rgba(97,223,202,.2)}
.concept-map-empty{padding:20px;border:1px dashed rgba(190,164,255,.24);border-radius:16px;color:var(--ink-soft);font-size:14px}
@keyframes concept-orbit-spin{to{transform:rotate(360deg)}}
@keyframes concept-edge-flow{to{stroke-dashoffset:-44}}
@keyframes concept-node-arrive{from{opacity:0;scale:.75}to{opacity:1;scale:1}}
@keyframes concept-node-pulse{0%,100%{stroke-opacity:.62}50%{stroke-opacity:1}}
@media(max-width:680px){.concept-map-controls{grid-template-columns:1fr}.concept-map-canvas{min-height:370px}.concept-map-orbit{inset:15% 5%}.concept-map-paper{padding:18px}}
@media(prefers-reduced-motion:reduce){.concept-map-paper,.concept-map-node circle,.concept-map-details button{transition:none}.concept-map-orbit,.concept-map-edge,.concept-map-node,.concept-map-node circle{animation:none!important}.concept-map-details button:hover{transform:none}}
.about,.capabilities,.studio,.progress,.revision,.concept-map{position:relative;isolation:isolate}
.about:before,.capabilities:before,.studio:before,.progress:before,.revision:before,.concept-map:before{content:"";position:absolute;top:4%;right:clamp(-92px,-5vw,-30px);z-index:-1;width:clamp(155px,20vw,240px);height:clamp(115px,15vw,180px);border:1px dashed rgba(190,164,255,.28);border-radius:50%;background:radial-gradient(circle at 50% 0%,rgba(97,223,202,.9) 0 2px,transparent 3px),radial-gradient(circle at 100% 50%,rgba(255,139,157,.85) 0 2px,transparent 3px),radial-gradient(circle at 50% 100%,rgba(176,151,255,.9) 0 2px,transparent 3px),radial-gradient(ellipse,rgba(128,94,255,.09),transparent 70%);opacity:.52;transform:rotate(-12deg);transition:opacity .3s ease,filter .3s ease;animation:section-orbit-drift 13s ease-in-out infinite}
.about:after,.capabilities:after,.studio:after,.progress:after,.revision:after,.concept-map:after{content:"";position:absolute;top:2%;right:clamp(-28px,1vw,18px);z-index:-1;width:92px;height:92px;pointer-events:none;background:radial-gradient(circle,rgba(245,240,255,.95) 0 1px,transparent 2px) 12px 14px/31px 31px,radial-gradient(circle,rgba(97,223,202,.9) 0 1.5px,transparent 2.5px) 3px 8px/47px 43px,radial-gradient(circle,rgba(255,139,157,.85) 0 1px,transparent 2px) 21px 2px/53px 51px;filter:drop-shadow(0 0 8px rgba(168,145,255,.38));opacity:.55;animation:section-stars-twinkle 4s ease-in-out infinite}
.about:hover:before,.about:focus-within:before,.capabilities:hover:before,.capabilities:focus-within:before,.studio:hover:before,.studio:focus-within:before,.progress:hover:before,.progress:focus-within:before,.revision:hover:before,.revision:focus-within:before,.concept-map:hover:before,.concept-map:focus-within:before{opacity:.9;filter:drop-shadow(0 0 12px rgba(128,94,255,.3))}
.capabilities:before,.capabilities:after{animation-delay:-1.2s}
.studio:before,.studio:after{animation-delay:-2.1s}
.progress:before,.progress:after{animation-delay:-3s}
.revision:before,.revision:after{animation-delay:-.6s}
.tool-card .icon{position:relative;isolation:isolate}
.tool-card .icon:after{content:"";position:absolute;inset:-5px;border:1px dashed rgba(211,193,255,.56);border-radius:17px;opacity:.48;transition:inset .25s ease,opacity .25s ease;animation:section-orbit-drift 11s linear infinite}
.tool-card:hover .icon:after,.tool-card:focus-within .icon:after{inset:-9px;opacity:1}
@keyframes section-orbit-drift{0%,100%{transform:rotate(-12deg) scale(.98)}50%{transform:rotate(12deg) scale(1.035)}}
@keyframes section-stars-twinkle{0%,100%{opacity:.36;filter:drop-shadow(0 0 3px rgba(168,145,255,.22));transform:translateY(0) scale(.96)}50%{opacity:.8;filter:drop-shadow(0 0 10px rgba(97,223,202,.48));transform:translateY(-4px) scale(1.04)}}
@media(max-width:680px){.about:before,.capabilities:before,.studio:before,.progress:before,.revision:before,.concept-map:before{right:-92px;width:150px;height:112px;opacity:.35}.about:after,.capabilities:after,.studio:after,.progress:after,.revision:after,.concept-map:after{right:-20px;opacity:.4}}
@media(prefers-reduced-motion:reduce){.about:before,.capabilities:before,.studio:before,.progress:before,.revision:before,.concept-map:before,.about:after,.capabilities:after,.studio:after,.progress:after,.revision:after,.concept-map:after,.tool-card .icon:after{animation:none!important;transition:none!important}.about:hover:before,.about:focus-within:before,.capabilities:hover:before,.capabilities:focus-within:before,.studio:hover:before,.studio:focus-within:before,.progress:hover:before,.progress:focus-within:before,.revision:hover:before,.revision:focus-within:before,.concept-map:hover:before,.concept-map:focus-within:before{transform:rotate(-12deg)}}
@media(prefers-reduced-motion:reduce){.orbit-track,.orbiting-satellites{animation:none!important}}
html{overflow-x:clip}
@media(max-width:680px){
  body{padding-bottom:calc(94px + env(safe-area-inset-bottom))}
  html{scroll-padding-bottom:calc(96px + env(safe-area-inset-bottom))}
  .top{gap:8px;padding:12px 12px 18px}
  .top nav{display:none}
  .mobile-nav{position:fixed;right:0;bottom:calc(9px + env(safe-area-inset-bottom));left:0;z-index:60;display:grid;width:min(460px,calc(100% - 24px));grid-template-columns:repeat(5,minmax(0,1fr));gap:3px;margin:0 auto;padding:7px;border:1px solid rgba(190,164,255,.24);border-radius:21px;background:rgba(27,22,52,.94);box-shadow:0 12px 38px rgba(5,3,19,.48),0 0 24px rgba(128,94,255,.12);-webkit-backdrop-filter:blur(20px) saturate(1.35);backdrop-filter:blur(20px) saturate(1.35)}
  .mobile-nav a{display:flex;min-width:0;min-height:52px;flex-direction:column;align-items:center;justify-content:center;gap:3px;border:1px solid transparent;border-radius:14px;color:rgba(239,232,255,.72);font-size:10px;font-weight:600;line-height:1;text-align:center;transition:background .2s ease,color .2s ease,transform .2s ease}
  .mobile-nav a svg{width:18px;height:18px;fill:none;stroke:currentColor;stroke-linecap:round;stroke-linejoin:round;stroke-width:1.7}
  .mobile-nav a:hover{color:#fff}
  .mobile-nav a[aria-current="location"]{transform:translateY(-2px);border-color:rgba(190,164,255,.26);background:linear-gradient(145deg,rgba(128,94,255,.29),rgba(232,86,145,.15));color:#fff;box-shadow:0 4px 14px rgba(128,94,255,.15)}
  .learning-orbit{max-width:430px}
}
@media(max-width:360px){.mobile-nav{width:calc(100% - 16px);padding:6px}.mobile-nav a{font-size:9px}}
@media(min-width:681px){.mobile-nav{display:none}}
@media(prefers-reduced-motion:reduce){.learning-orbit-mobile-constellation path,.learning-orbit-mobile-constellation circle,.mobile-nav a{animation:none!important;transition:none!important}.mobile-nav a[aria-current="location"]{transform:none}}
</style>
</head>
<body>
<header class="top"><a class="name" href="#home" aria-label="StuDyEaSe home"><span class="name-mark" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none"><path d="M3 6.3c3.1-.8 6.1-.2 9 1.8v12c-2.9-2-5.9-2.6-9-1.8v-12Zm18 0c-3.1-.8-6.1-.2-9 1.8v12c2.9-2 5.9-2.6 9-1.8v-12Z" fill="rgba(255,255,255,.18)" stroke="white" stroke-width="1.5" stroke-linejoin="round"/><path d="M17.5 2.5v5m-2.5-2.5h5" stroke="#ffe28a" stroke-width="1.8" stroke-linecap="round"/></svg></span>StuDyEaSe</a><button class="account-button" id="accountButton" type="button">Sign up</button><nav aria-label="Main navigation"><a href="#home" aria-current="location">Home</a><a href="#features">Learning paths</a><a href="#studio">Learning studio</a><a href="#tools">Study tools</a><a href="#concept-map">Concept map</a><a href="#revision">Smart revision</a><a href="#journey">Your progress</a><a class="nav-start" href="#studio">Begin learning&nbsp; &#8599;</a></nav></header>
<nav class="mobile-nav" aria-label="Mobile navigation">
<a href="#home" aria-current="location"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="m3 10 9-7 9 7v10a1 1 0 0 1-1 1h-5v-7H9v7H4a1 1 0 0 1-1-1z"/></svg><span>Home</span></a>
<a href="#studio"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 3a6 6 0 0 0-3.8 10.6c.8.7 1.3 1.7 1.3 2.9h5c0-1.2.5-2.2 1.3-2.9A6 6 0 0 0 12 3Z"/><path d="M9.8 20h4.4m-3.8-3.5h3.2M12 0v1m-9 3 1 .6m16-1-1 .6M2 12h1m18 0h1"/></svg><span>Learn</span></a>
<a href="#tools"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M5 4.5h14v16H5zM8 8h8M8 12h8m-8 4h5"/><path d="M8 2.5v4m8-4v4"/></svg><span>Tools</span></a>
<a href="#concept-map"><svg viewBox="0 0 24 24" aria-hidden="true"><circle cx="12" cy="12" r="3"/><circle cx="5" cy="5" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="19" cy="19" r="2"/><path d="m7 6.5 3 3m7-3-3 3m-7 8 3-3m7 3-3-3"/></svg><span>Map</span></a>
<a href="#journey"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M4 19V9m5 10V5m5 14v-7m5 7V3M2 21h20"/></svg><span>Progress</span></a>
</nav>
<main class="page">
<section class="hero" id="home" aria-labelledby="heroTitle"><p class="hero-kicker">A brighter place for curious minds</p><h1 id="heroTitle">Learn with a little<br><em>more ease.</em></h1><p class="hero-intro">Explore ideas, master concepts, and make learning personal with AI.</p><div class="hero-highlights" aria-label="A little inspiration"><span>Follow your curiosity</span><span>Big ideas, made simple</span><span>Discover something new</span></div>
<div class="learning-orbit" role="group" aria-label="Interactive learning paths">
<div class="constellation-sparkles" aria-hidden="true"><span>✦</span><span>✦</span><span>✧</span><span>✦</span></div>
<svg viewBox="0 0 760 350" role="group" aria-label="Learning constellation">
<defs><radialGradient id="ideaGlow" cx="35%" cy="25%" r="80%"><stop stop-color="#967cff"/><stop offset="1" stop-color="#5545e8"/></radialGradient></defs>
<ellipse class="orbit-track" cx="380" cy="170" rx="224" ry="106"/>
<g class="orbiting-satellites" aria-hidden="true"><circle cx="604" cy="170" r="4"/><circle cx="156" cy="170" r="3"/><circle cx="430" cy="66" r="2"/></g>
<path class="orbit-link" d="M250 105 333 148M510 105 427 148M250 235l83-43m177 43-83-43"/>
<path class="orbit-link orbit-revision-link" d="M380 240v35"/>
<circle class="orbit-spark" cx="270" cy="116" r="3"/><circle class="orbit-spark" cx="489" cy="222" r="3"/>
<g class="orbit-node orbit-card-node orbit-trigger" role="button" tabindex="0" aria-pressed="false" aria-label="Ask: start with a question" data-title="Ask a question" data-description="Choose a topic you want to understand. The learning studio will shape a clear explanation around it." data-link="#studio" data-link-label="Open the learning studio">
<rect class="orbit-card" x="105" y="72" width="150" height="58" rx="17"/>
<circle cx="132" cy="101" r="15" fill="#eeeaff"/>
<path class="orbit-icon" d="M125 98h14m-14 6h9m-10 8-3 4v-7"/>
<text class="orbit-card-title" x="156" y="98">ASK</text><text class="orbit-card-subtitle" x="156" y="114">Start with a question</text>
</g>
<g class="orbit-node orbit-card-node orbit-trigger" role="button" tabindex="0" aria-pressed="false" aria-label="Practice: build what you know" data-title="Practice what you know" data-description="Try a short quiz to check your understanding, get feedback on each answer, and learn as you go." data-link="#tools" data-link-label="Try a quiz">
<rect class="orbit-card" x="505" y="72" width="150" height="58" rx="17"/>
<circle cx="532" cy="101" r="15" fill="#fff0e9"/>
<path class="orbit-icon" d="m526 101 4 4 8-9" style="stroke:#ff795c"/>
<text class="orbit-card-title" x="556" y="98">PRACTICE</text><text class="orbit-card-subtitle" x="556" y="114">Build what you know</text>
</g>
<g class="orbit-node orbit-card-node orbit-trigger" role="button" tabindex="0" aria-pressed="false" aria-label="Explore: find a clearer way" data-title="Explore the idea" data-description="Get a clear explanation tailored to your learning level, with examples and different ways to approach the topic." data-link="#studio" data-link-label="Explore a topic">
<rect class="orbit-card" x="105" y="210" width="150" height="58" rx="17"/>
<circle cx="132" cy="239" r="15" fill="#e5f8f5"/>
<path class="orbit-icon" d="M132 229v10l7 4m-7-16a12 12 0 1 0 12 12" style="stroke:#087f8c"/>
<text class="orbit-card-title" x="156" y="236">EXPLORE</text><text class="orbit-card-subtitle" x="156" y="252">Find a clearer way</text>
</g>
<g class="orbit-node orbit-card-node orbit-trigger" role="button" tabindex="0" aria-pressed="false" aria-label="Grow: track your progress" data-title="See how far you have come" data-description="Your learning journal keeps a small record of explored topics, completed quizzes, and your quiz accuracy on this device." data-link="#journey" data-link-label="View your progress">
<rect class="orbit-card" x="505" y="210" width="150" height="58" rx="17"/>
<circle cx="532" cy="239" r="15" fill="#fff0e9"/>
<path class="orbit-icon" d="M526 245v-7m6 7v-13m6 13v-10" style="stroke:#ff795c"/>
<text class="orbit-card-title" x="556" y="236">GROW</text><text class="orbit-card-subtitle" x="556" y="252">Track your progress</text>
</g>
<g class="orbit-node orbit-card-node orbit-trigger orbit-revision-node" role="button" tabindex="0" aria-pressed="false" aria-label="Revise: revisit tricky questions" data-title="Make what you learn stick" data-description="Revisit every quiz question you missed in the smart revision desk. Flip a card to reveal the answer, then mark it to review again or as known." data-link="#revision" data-link-label="Open smart revision">
<rect class="orbit-card" x="305" y="275" width="150" height="55" rx="17"/>
<circle cx="332" cy="302" r="15" fill="#d9fff6"/>
<path class="orbit-icon" d="M326 302a6 6 0 0 1 10-4l2 2m0-5v5h-5m5 4a6 6 0 0 1-10 4l-2-2m0 5v-5h5" style="stroke:#087f8c"/>
<text class="orbit-card-title" x="356" y="300">REVISE</text><text class="orbit-card-subtitle" x="356" y="316">Make it stick</text>
</g>
<path class="orbit-link orbit-revision-link" d="M380 59v5"/>
<g class="orbit-node orbit-card-node orbit-trigger orbit-map-node" role="button" tabindex="0" aria-pressed="false" aria-label="Map: connect the ideas" data-title="See how the ideas connect" data-description="Build an interactive concept map. Choose a concept to explore its meaning and how it links to the main topic." data-link="#concept-map" data-link-label="Open the concept map">
<rect class="orbit-card" x="305" y="6" width="150" height="53" rx="17"/>
<circle cx="332" cy="32" r="15" fill="#eeeaff"/>
<path class="orbit-icon" d="M332 25v14m-7-7h14m-12-5-3-3m14 14 3 3" style="stroke:#a891ff"/>
<text class="orbit-card-title" x="356" y="30">MAP</text><text class="orbit-card-subtitle" x="356" y="46">Connect the ideas</text>
</g>
<g class="orbit-node idea-node orbit-trigger" role="button" tabindex="0" aria-pressed="false" aria-label="Learning constellation: discover the learning paths" data-title="Choose your learning path" data-description="Ask a question, explore a clear explanation, practise with a quiz, review missed questions, and watch your progress grow. Learning gets stronger when you revisit the tricky bits." data-link="#features" data-link-label="See all learning paths">
<circle class="idea-ripple" cx="380" cy="170" r="66"/>
<circle class="idea-ripple ripple-two" cx="380" cy="170" r="66"/>
<circle class="idea-glow" cx="380" cy="170" r="63"/>
<circle class="orbit-core-outline" cx="380" cy="170" r="76" fill="none" stroke="#5545e8" stroke-opacity=".42" stroke-width="1.5"/>
<path class="idea-icon" d="M380 128c-16 0-28 12-28 27 0 11 6 18 13 24 4 4 6 8 6 13h18c0-5 2-9 6-13 7-6 13-13 13-24 0-15-12-27-28-27Zm-9 70h18m-16 8h14"/>
<path class="idea-icon" d="m380 115 2 6m-47 12 5 4m82-4-5 4" opacity=".72"/>
</g>
</svg>
<div class="learning-orbit-mobile orbit-mobile-paths" role="group" aria-label="Choose a learning path">
<svg class="learning-orbit-mobile-constellation" viewBox="0 0 360 410" preserveAspectRatio="none" aria-hidden="true">
<path d="M180 58v27M180 85 90 122m90-37 90 37M90 122v95m180-95v95M90 217v100m180-100v100M90 317v80m180-80v80M90 217h180M90 317h180"/>
<circle cx="180" cy="84" r="3"/><circle cx="90" cy="121" r="3"/><circle cx="270" cy="121" r="3"/><circle cx="90" cy="217" r="2.5"/><circle cx="270" cy="217" r="2.5"/><circle cx="90" cy="317" r="2.5"/><circle cx="270" cy="317" r="2.5"/>
</svg>
<button class="orbit-mobile-node orbit-mobile-center orbit-trigger" type="button" aria-pressed="false" data-title="Choose your learning path" data-description="Ask a question, explore a clear explanation, practise with a quiz, review missed questions, and watch your progress grow. Learning gets stronger when you revisit the tricky bits." data-link="#features" data-link-label="See all learning paths"><strong>Learning, connected</strong><span>Tap to see how each path fits together.</span></button>
<button class="orbit-mobile-node orbit-trigger" type="button" aria-pressed="false" data-title="Ask a question" data-description="Choose a topic you want to understand. The learning studio will shape a clear explanation around it." data-link="#studio" data-link-label="Open the learning studio"><strong>Ask a question</strong><span>Start with something you want to understand.</span></button>
<button class="orbit-mobile-node orbit-trigger" type="button" aria-pressed="false" data-title="Practice what you know" data-description="Try a short quiz to check your understanding, get feedback on each answer, and learn as you go." data-link="#tools" data-link-label="Try a quiz"><strong>Practice</strong><span>Build confidence with a quick quiz.</span></button>
<button class="orbit-mobile-node orbit-trigger" type="button" aria-pressed="false" data-title="Explore the idea" data-description="Get a clear explanation tailored to your learning level, with examples and different ways to approach the topic." data-link="#studio" data-link-label="Explore a topic"><strong>Explore</strong><span>Find a clearer way to learn a concept.</span></button>
<button class="orbit-mobile-node orbit-trigger" type="button" aria-pressed="false" data-title="See how far you have come" data-description="Your learning journal keeps a small record of explored topics, completed quizzes, and your quiz accuracy on this device." data-link="#journey" data-link-label="View your progress"><strong>Grow</strong><span>See your learning progress over time.</span></button>
<button class="orbit-mobile-node orbit-trigger orbit-mobile-revision" type="button" aria-pressed="false" data-title="Make what you learn stick" data-description="Revise every quiz question you missed in the smart revision desk. Flip a card to reveal the answer, then mark it to revisit or as known." data-link="#revision" data-link-label="Open smart revision"><strong>Revise & remember</strong><span>Flip flashcards and revisit every tricky answer.</span></button>
<button class="orbit-mobile-node orbit-trigger" type="button" aria-pressed="false" data-title="See how the ideas connect" data-description="Build an interactive concept map. Choose a concept to explore its meaning and how it links to the main topic." data-link="#concept-map" data-link-label="Open the concept map"><strong>Map the ideas</strong><span>See how a topic's key concepts connect.</span></button>
</div>
</div>
<dialog class="orbit-dialog" id="orbitDialog" aria-labelledby="orbitDialogTitle" aria-describedby="orbitDialogDescription"><button class="orbit-dialog-close" id="orbitDialogClose" type="button" aria-label="Close learning path details">&times;</button><h2 id="orbitDialogTitle"></h2><p id="orbitDialogDescription"></p><a id="orbitDialogLink"></a></dialog>
<dialog class="clear-progress-dialog" id="clearProgressDialog" aria-labelledby="clearProgressTitle" aria-describedby="clearProgressDescription"><button class="orbit-dialog-close" id="clearProgressDialogClose" type="button" aria-label="Cancel clearing progress">&times;</button><div class="clear-dialog-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"><path d="M4 7h16m-13 0 1 13h8l1-13M9 7V4h6v3m-4 4v5m2-5v5"/></svg></div><h2 id="clearProgressTitle">Clear your progress?</h2><p id="clearProgressDescription">This removes your saved learning activity, quiz attempts, and stats. This action can’t be undone.</p><div class="clear-dialog-actions"><button class="clear-dialog-cancel" id="cancelClearProgress" type="button">Keep my progress</button><button class="clear-dialog-confirm" id="confirmClearProgress" type="button">Clear progress</button></div></dialog>
<div class="hero-idea-prompt"><span class="hero-idea-icon" aria-hidden="true">✦</span><span><strong>Choose a spark to begin.</strong><small>Tap any topic below and your explanation will open in the learning studio.</small></span></div><p class="hint">Pick a topic, choose how you like to learn, and explore.</p><div class="topic-sparks" role="group" aria-label="Choose a topic to get an explanation"><span class="topic-sparks-label">Need an idea? Tap one to see its explanation</span><button class="topic-spark" type="button" data-topic="Black holes">Black holes</button><button class="topic-spark" type="button" data-topic="Photosynthesis">Photosynthesis</button><button class="topic-spark" type="button" data-topic="The human brain">The human brain</button><button class="topic-spark" type="button" data-topic="The French Revolution">The French Revolution</button><button class="topic-spark topic-spark-surprise" id="surpriseTopic" type="button">Surprise me&nbsp; ✦</button></div><button class="hero-down" id="heroDown" type="button" aria-label="Scroll to learning paths"><svg viewBox="0 0 44 22" width="34" height="17" fill="none" aria-hidden="true"><path d="m3 4 19 8L41 4M3 11l19 8 19-8" stroke="currentColor" stroke-width="1.1" stroke-linecap="round" stroke-linejoin="round"/></svg></button></section>
<div class="rule" aria-hidden="true"></div>
<section class="about reveal" id="about"><div class="about-copy"><p class="section-label">A note on learning</p><h2 class="section-title">Understanding starts<br>with a good question.</h2><p class="section-copy">StuDyEaSe makes room for the way you learn: clear explanations, useful practice, and thoughtful notes, all shaped around the topic you bring.</p></div><svg class="about-mark" viewBox="0 0 220 220" fill="none" aria-hidden="true"><circle cx="110" cy="110" r="78" stroke="#95683f" stroke-opacity=".42"/><circle cx="110" cy="110" r="58" stroke="#75836b" stroke-opacity=".45" stroke-dasharray="1 7"/><path d="M110 45v130m-65-65h130M64 64l92 92m0-92-92 92" stroke="#95683f" stroke-opacity=".48"/><path d="M110 69c-20 0-33 14-33 32 0 17 14 25 20 35h26c6-10 20-18 20-35 0-18-13-32-33-32Zm-11 78h22m-20 8h18" stroke="#2b2721" stroke-opacity=".55" stroke-linecap="round"/><circle cx="110" cy="110" r="5" fill="#95683f"/></svg></section>
<div class="rule short" aria-hidden="true"></div>
<section class="capabilities reveal" id="features"><p class="section-label">A few ways to begin</p><h2 class="section-title">A study desk for every idea.</h2><ol class="plate-list"><li><a class="plate" href="#studio"><span class="n">01</span><span class="t">Explanations that meet you where you are</span><span class="p">Understand a concept</span></a></li><li><a class="plate" href="#tools"><span class="n">02</span><span class="t">Notes that give your study session shape</span><span class="p">Review and practise</span></a></li><li><a class="plate" href="#tools"><span class="n">03</span><span class="t">A little practice to make ideas stay</span><span class="p">Take a short quiz</span></a></li><li><a class="plate" href="#journey"><span class="n">04</span><span class="t">A quiet record of what you&#8217;ve explored</span><span class="p">See your progress</span></a></li><li><a class="plate plate-revision" href="#revision"><span class="n">05</span><span class="t">Revisit the tricky bits with smart flashcards</span><span class="p">Make learning stick</span></a></li><li><a class="plate plate-concept-map" href="#concept-map"><span class="n">06</span><span class="t">See how the big ideas fit together</span><span class="p">Explore a concept map</span></a></li></ol></section>
<div class="rule" aria-hidden="true"></div>
<section class="studio" id="studio"><div class="studio-heading reveal"><div><p class="section-label">Your learning studio</p><h2 class="section-title">Let&#8217;s open<br>the subject.</h2></div><p class="section-copy">Choose a topic, tell us how you like to learn, and settle into a clear explanation.</p></div><div class="studio-paper reveal"><div class="desk-sparkles" aria-hidden="true"><span>✦</span><span>✧</span><span>✦</span></div><div class="controls"><div class="field"><label for="topic">What are you learning?</label><input id="topic" maxlength="180" placeholder="e.g. How do black holes work?"></div><div class="field"><label for="level">Learning level</label><select id="level"><option>Curious learner</option><option>Middle school</option><option>High school</option><option>College</option><option>Advanced</option></select></div><button class="primary" id="explainBtn" type="button">Explain this&nbsp; &#8599;</button></div><div class="style-tabs" role="group" aria-label="Explanation style"><button class="style-tab active" type="button" data-style="simple">Simple explanation</button><button class="style-tab" type="button" data-style="steps">Step by step</button><button class="style-tab" type="button" data-style="examples">Real-life examples</button></div><div class="output" id="explanation" aria-live="polite"><div class="empty">Your next &ldquo;aha&rdquo; moment begins with a question above.</div></div></div></section>
<div class="rule short" aria-hidden="true"></div>
<section class="capabilities reveal" aria-labelledby="toolsTitle" id="tools"><p class="section-label">The study toolkit</p><h2 class="section-title" id="toolsTitle">Pages for practice<br>and remembering.</h2><p class="section-copy">Create a short quiz or gather the essentials for your next study session.</p><div class="split"><article class="tool-card"><div class="icon" aria-hidden="true">Q</div><h3>Quiz arena</h3><p class="subtle">A quick challenge makes new knowledge stick.</p><div class="field"><label for="quizTopic">Quiz topic</label><input id="quizTopic" maxlength="180" placeholder="e.g. The water cycle"></div><button class="primary" id="quizBtn" type="button">Prepare my quiz&nbsp; &#8599;</button><div class="output quiz-area" id="quizOutput" aria-live="polite"><div class="empty">Your quiz will appear here. Take your time&mdash;learning isn&#8217;t a race.</div></div></article><article class="tool-card"><div class="icon" aria-hidden="true">N</div><h3>Study notes</h3><p class="subtle">A summary, revision notes, and prompts, in one considered set.</p><div class="field"><label for="studyTopic">Study topic</label><input id="studyTopic" maxlength="180" placeholder="e.g. Photosynthesis"></div><button class="primary" id="studyBtn" type="button">Gather my notes&nbsp; &#8599;</button><div class="output" id="studyOutput" aria-live="polite"><div class="empty">Your notes and practice prompts will appear here.</div></div></article></div></section>
<div class="rule" aria-hidden="true"></div>
<section class="concept-map reveal" id="concept-map" aria-labelledby="conceptMapTitle"><p class="section-label">Ideas in orbit</p><div class="studio-heading"><div><h2 class="section-title" id="conceptMapTitle">See the connections.</h2></div><p class="section-copy">Turn any subject into an interactive constellation of ideas. Select a node to explore what it means and how it connects.</p></div><div class="concept-map-paper"><div class="concept-map-controls"><div class="field"><label for="mapTopic">What topic should we map?</label><input id="mapTopic" maxlength="180" placeholder="e.g. How ecosystems work"></div><button class="primary" id="conceptMapBtn" type="button">Build my concept map&nbsp; ✦</button></div><p class="concept-map-hint">Choose a node to explore its meaning. Related concepts are linked around your main topic.</p><div class="concept-map-output" id="conceptMapOutput" aria-live="polite"><div class="concept-map-empty">Enter a subject above to set your ideas in motion.</div></div></div></section>
<div class="rule" aria-hidden="true"></div>
<section class="progress reveal" id="journey"><p class="section-label">Your learning journal</p><h2 class="section-title">Progress, at your own pace.</h2><p class="section-copy">A small record of the topics you&#8217;ve explored on this device.</p><div class="progress-paper"><div class="progress-grid"><div class="metric"><strong id="activityCount">?</strong><span>Learning activities</span></div><div class="metric"><strong id="quizCount">?</strong><span>Quizzes completed</span></div><div class="metric"><strong id="accuracy">?</strong><span>Quiz accuracy</span></div></div><div class="topic-list" id="topicList" aria-live="polite"><div class="empty">Your learning history will appear here as you explore.</div></div><div class="chat-history"><div class="chat-history-heading"><h3>Learning history</h3><span>Explanations, notes, quizzes, and concept maps</span></div><div class="chat-history-list" id="chatHistoryList" aria-live="polite"><div class="empty">Your learning activities will appear here as you explore.</div></div></div><div class="progress-actions"><button class="clear-progress" id="clearProgressBtn" type="button"><svg viewBox="0 0 20 20" width="14" height="14" aria-hidden="true"><path d="M4 6h12m-10 0 1 11h6l1-11m-5-2h4m-5 0 1-2h4l1 2m-4 5v5m3-5v5" fill="none" stroke="currentColor" stroke-linecap="round" stroke-linejoin="round" stroke-width="1.6"/></svg>Clear all progress</button></div></div></section>
<section class="revision reveal" id="revision" aria-labelledby="revisionTitle"><p class="section-label">Make it stick</p><h2 class="section-title" id="revisionTitle">Your smart revision desk.</h2><p class="section-copy">Revise every quiz question you missed, all in one place. Flip each card, check the answer, then tell us if it feels familiar.</p><div class="revision-layout"><article class="revision-panel" aria-labelledby="dailyReviewTitle"><div class="revision-panel-heading"><h3 id="dailyReviewTitle">Your revision queue</h3><span class="pill" id="revisionDue">Loading your deck…</span></div><div id="revisionContent" aria-live="polite"><div class="empty">Getting your revision cards ready…</div></div></article><aside class="revision-panel" aria-labelledby="weakTopicsTitle"><p class="section-label">Your next best step</p><div class="revision-stat"><strong id="revisionMastery">0%</strong><span>cards marked as known</span></div><p class="revision-caption" id="revisionMasteryCaption">Mastery grows as you revisit tricky questions.</p><h3 id="weakTopicsTitle" style="margin:23px 0 0;color:var(--ink);font:400 25px/1.2 var(--display)">Topics to revisit</h3><div class="weak-topic-list" id="weakTopicList" aria-live="polite"><div class="empty">Your quiz results will suggest what to revisit here.</div></div></aside></div></section>
</main>
<footer id="contact"><div class="footer-row"><a href="#home" class="brand"><span class="logo" aria-hidden="true">S</span>StuDyEaSe</a><nav class="foot-links" aria-label="Footer navigation"><a href="#studio">Learning studio</a><a href="#tools">Study notes &amp; quiz</a><a href="#journey">Learning journal</a></nav><a class="nav-cta" href="#home">Back to the beginning&nbsp; &#8599;</a></div><p class="fine">Understand EASY. Learn More. &nbsp;&middot;&nbsp; AI explanations are learning support. Check important information against trusted sources.</p></footer>
<div class="toast" id="toast" role="status" aria-live="polite"></div>
<dialog class="account-dialog" id="accountDialog" aria-labelledby="accountDialogTitle">
<button class="orbit-dialog-close" id="accountDialogClose" type="button" aria-label="Close account dialog">&times;</button>
<h2 id="accountDialogTitle">Your learning account</h2><p class="account-intro">Sign in to keep your progress together across sessions.</p>
<div id="authForms">
<div class="account-tabs" role="group" aria-label="Choose sign-in or sign-up"><button type="button" data-auth-mode="login" aria-pressed="true">Sign in</button><button type="button" data-auth-mode="signup" aria-pressed="false">Create account</button></div>
<form class="account-form" id="loginForm">
<label>Email or username<input name="identifier" autocomplete="username" required maxlength="254" placeholder="you@example.com or username"></label>
<label>Password<input name="password" type="password" autocomplete="current-password" required maxlength="128" placeholder="Your password"></label>
<button class="primary" type="submit">Sign in</button>
</form>
<form class="account-form" id="signupForm" hidden>
<label>Username<input name="username" autocomplete="username" required minlength="3" maxlength="30" pattern="[A-Za-z0-9_.\-]{3,30}" placeholder="Choose a username"></label>
<label>Email<input name="email" type="email" autocomplete="email" required maxlength="254" placeholder="you@example.com"></label>
<label>Password<input name="password" type="password" autocomplete="new-password" required minlength="8" maxlength="128" placeholder="At least 8 characters"></label>
<button class="primary" type="submit">Create my account</button>
</form>
<p class="auth-message" id="authMessage" role="status" aria-live="polite"></p>
</div>
<div id="signedInPanel" hidden><div class="signed-in-card"><strong id="signedInName"></strong><p id="signedInEmail"></p><p>Your progress is saved to this account.</p></div><button class="account-signout" id="signOutBtn" type="button">Sign out</button></div>
</dialog>
<script>
let csrfToken=document.querySelector('meta[name="csrf-token"]').content;
const $=s=>document.querySelector(s);
const accountDialog=$('#accountDialog');
function showAuthMode(mode){document.querySelectorAll('[data-auth-mode]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.authMode===mode)));$('#loginForm').hidden=mode!=='login';$('#signupForm').hidden=mode!=='signup';$('#authMessage').textContent=''}
function updateAccount(data){if(data.csrf_token)csrfToken=data.csrf_token;const authenticated=Boolean(data.authenticated);$('#accountButton').textContent=authenticated?data.username:'Sign up';$('#authForms').hidden=authenticated;$('#signedInPanel').hidden=!authenticated;if(authenticated){$('#signedInName').textContent='@'+data.username;$('#signedInEmail').textContent=data.email}return authenticated}
async function refreshAccount(){const response=await fetch('/api/auth/status');if(!response.ok)throw Error('Could not check your account status.');const data=await response.json();updateAccount(data)}
$('#accountButton').addEventListener('click',()=>{if($('#signedInPanel').hidden)showAuthMode('signup');accountDialog.showModal()});
$('#accountDialogClose').addEventListener('click',()=>accountDialog.close());
accountDialog.addEventListener('click',event=>{if(event.target===accountDialog)accountDialog.close()});
document.querySelectorAll('[data-auth-mode]').forEach(button=>button.addEventListener('click',()=>showAuthMode(button.dataset.authMode)));
$('#loginForm').addEventListener('submit',async event=>{event.preventDefault();const data=Object.fromEntries(new FormData(event.currentTarget));$('#authMessage').textContent='';try{updateAccount(await api('/api/auth/login',data));accountDialog.close();loadProgress();loadChatHistory()}catch(error){$('#authMessage').textContent=error.message}});
$('#signupForm').addEventListener('submit',async event=>{event.preventDefault();const data=Object.fromEntries(new FormData(event.currentTarget));$('#authMessage').textContent='';try{updateAccount(await api('/api/auth/signup',data));accountDialog.close();loadProgress();loadChatHistory()}catch(error){$('#authMessage').textContent=error.message}});
$('#signOutBtn').addEventListener('click',async()=>{try{updateAccount(await api('/api/auth/logout',{}));accountDialog.close();loadProgress();loadChatHistory()}catch(error){$('#authMessage').textContent=error.message}});
const clearProgressDialog=$('#clearProgressDialog');
let clearingProgress=false;
$('#clearProgressBtn').addEventListener('click',()=>{const isGuest=$('#signedInPanel').hidden;$('#clearProgressDescription').textContent=isGuest?'This removes learning activity, quiz attempts, and stats saved on this device. This action can’t be undone.':'This removes learning activity, quiz attempts, and stats saved to your account. This action can’t be undone.';clearProgressDialog.showModal()});
$('#clearProgressDialogClose').addEventListener('click',()=>clearProgressDialog.close());
$('#cancelClearProgress').addEventListener('click',()=>clearProgressDialog.close());
clearProgressDialog.addEventListener('click',event=>{if(event.target===clearProgressDialog)clearProgressDialog.close()});
$('#confirmClearProgress').addEventListener('click',async()=>{if(clearingProgress)return;clearingProgress=true;const confirmButton=$('#confirmClearProgress'),paper=$('.progress-paper');confirmButton.disabled=true;confirmButton.textContent='Clearing…';clearProgressDialog.close();paper.classList.remove('is-clearing');void paper.offsetWidth;paper.classList.add('is-clearing');try{await Promise.all([api('/api/progress/clear',{confirmed:true}),new Promise(resolve=>setTimeout(resolve,matchMedia('(prefers-reduced-motion: reduce)').matches?0:560))]);paper.classList.remove('is-clearing');await Promise.all([loadProgress(),loadChatHistory()]);paper.classList.remove('progress-cleared');void paper.offsetWidth;paper.classList.add('progress-cleared');setTimeout(()=>paper.classList.remove('progress-cleared'),500);toast('Progress cleared.')}catch(error){paper.classList.remove('is-clearing');toast(error.message)}finally{clearingProgress=false;confirmButton.disabled=false;confirmButton.textContent='Clear progress'}});
refreshAccount().catch(error=>toast(error.message));
const orbitNodes=[...document.querySelectorAll('.orbit-trigger')];
const orbitDialog=document.getElementById('orbitDialog');
orbitNodes.forEach(node=>{
	const activate=()=>{
		orbitNodes.forEach(item=>item.setAttribute('aria-pressed',String(item===node)));
		document.getElementById('orbitDialogTitle').textContent=node.dataset.title;
		document.getElementById('orbitDialogDescription').textContent=node.dataset.description;
		const link=document.getElementById('orbitDialogLink');
		link.href=node.dataset.link;
		link.textContent=node.dataset.linkLabel;
		if(!orbitDialog.open)orbitDialog.showModal();
	};
	node.addEventListener('click',activate);
	node.addEventListener('keydown',event=>{
		if(node instanceof HTMLButtonElement)return;
		if(event.key==='Enter'||event.key===' '){event.preventDefault();activate()}
	});
});
document.getElementById('orbitDialogClose').addEventListener('click',()=>orbitDialog.close());
orbitDialog.addEventListener('click',event=>{if(event.target===orbitDialog)orbitDialog.close()});
orbitDialog.addEventListener('cancel',event=>{event.preventDefault();orbitDialog.close()});
orbitDialog.addEventListener('keydown',event=>{if(event.key==='Escape'){event.preventDefault();orbitDialog.close()}});
orbitDialog.addEventListener('close',()=>orbitNodes.forEach(node=>node.setAttribute('aria-pressed','false')));
document.getElementById('orbitDialogLink').addEventListener('click',()=>orbitDialog.close());
document.getElementById('heroDown').addEventListener('click',()=>document.getElementById('features').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'start'}));
const sectionLinks=[...document.querySelectorAll('.top nav a[href^="#"],.mobile-nav a[href^="#"]')];
const pageSections=sectionLinks.map(link=>[link,document.querySelector(link.getAttribute('href'))]).filter(([,section])=>section);
const markCurrentSection=()=>{let current=pageSections[0]?.[0].getAttribute('href');for(const [link,section] of pageSections){if(section.getBoundingClientRect().top<=window.innerHeight*.3)current=link.getAttribute('href')}sectionLinks.forEach(link=>{if(link.getAttribute('href')===current)link.setAttribute('aria-current','location');else link.removeAttribute('aria-current')})};
addEventListener('scroll',markCurrentSection,{passive:true});markCurrentSection();
let learningStyle='simple', currentQuiz=null, questionIndex=0, quizScore=0, explanationRequest=0, lastSuggestedTopic='';

async function api(path,payload){const response=await fetch(path,{method:'POST',headers:{'Content-Type':'application/json','X-CSRF-Token':csrfToken},body:JSON.stringify(payload)});let data;try{data=await response.json()}catch{throw Error('The server returned an unreadable response.')}if(data.csrf_token)csrfToken=data.csrf_token;if(!response.ok)throw Error(data.error||'Something went wrong.');return data}
async function getJSON(path,errorMessage='Could not load your chat history.'){const response=await fetch(path);let data;try{data=await response.json()}catch{throw Error('The server returned an unreadable response.')}if(!response.ok)throw Error(data.error||errorMessage);return data}

function toast(message){const el=$('#toast');el.textContent=message;el.classList.add('show');clearTimeout(toast.t);toast.t=setTimeout(()=>el.classList.remove('show'),3800)}

function setBusy(button,on,label){button.disabled=on;button.innerHTML=on?'<span class="loader"></span>Working…':label}

function safeText(value){return String(value??'')}

function escapeHTML(value){return safeText(value).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}

function needTopic(el){const value=el.value.trim();if(!value){el.focus();toast('Add a topic first, and we’ll take it from there.');return ''}return value}

document.querySelectorAll('.style-tab[data-style]').forEach(btn=>btn.addEventListener('click',()=>{document.querySelectorAll('.style-tab[data-style]').forEach(b=>b.classList.remove('active'));btn.classList.add('active');learningStyle=btn.dataset.style;if($('#topic').value.trim())runExplanation()}));

const topicSparkButtons=[...document.querySelectorAll('[data-topic]')];
function startTopic(topic){lastSuggestedTopic=topic;$('#topic').value=topic;document.getElementById('studio').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'start'});runExplanation().then(()=>document.getElementById('explanation').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'center'}))}
topicSparkButtons.forEach(button=>button.addEventListener('click',()=>startTopic(button.dataset.topic)));
$('#surpriseTopic').addEventListener('click',()=>{const topics=topicSparkButtons.map(button=>button.dataset.topic).filter(topic=>topic!==lastSuggestedTopic);startTopic(topics[Math.floor(Math.random()*topics.length)]||topicSparkButtons[0].dataset.topic)});

function explanationMarkup(d,topic){const sections=Array.isArray(d.sections)?d.sections:[];return `<article class="result-card"><h3>${escapeHTML(d.title||topic)}</h3><p>${escapeHTML(d.overview||'')}</p>${sections.map(s=>`<h4>${escapeHTML(s.heading||'Explore')}</h4><p>${escapeHTML(s.text||'')}</p>`).join('')}<h4>A helpful example</h4><p>${escapeHTML(d.example||'')}</p>${d.diagram?`<h4>See the connection</h4><div class="diagram">${escapeHTML(d.diagram)}</div>`:''}<h4>Keep in mind</h4><div class="takeaways">${(Array.isArray(d.takeaways)?d.takeaways:[]).map(t=>`<div>✦ &nbsp;${escapeHTML(t)}</div>`).join('')}</div></article>`}
function studyMarkup(d){return `<article class="result-card"><h4>Quick summary</h4><p>${escapeHTML(d.summary||'')}</p><h4>Revision notes</h4><ul class="notes-list">${(Array.isArray(d.notes)?d.notes:[]).map(item=>`<li>${escapeHTML(item)}</li>`).join('')}</ul><h4>Practice questions</h4><ol class="notes-list">${(Array.isArray(d.practice)?d.practice:[]).map(item=>`<li>${escapeHTML(item)}</li>`).join('')}</ol><div class="empty">Memory tip: ${escapeHTML(d.memory_tip||'')}</div></article>`}
function quizHistoryMarkup(item){const questions=Array.isArray(item.result.questions)?item.result.questions:[],answers=Array.isArray(item.answers)?item.answers:[],score=item.score;return `<article class="result-card"><h3>${escapeHTML(item.topic)} quiz</h3><p>${score?`Score: ${Number(score.score)} / ${Number(score.total)}.`:'This quiz was saved before it was completed.'}</p>${questions.map((question,index)=>{const selected=answers[index],correct=question.answer;return `<section class="history-quiz-question"><h4>${index+1}. ${escapeHTML(question.question||'')}</h4><ol type="A">${(Array.isArray(question.choices)?question.choices:[]).map((choice,choiceIndex)=>`<li class="${choiceIndex===correct?'correct':choiceIndex===selected&&selected!==correct?'wrong':''}">${escapeHTML(choice)}${choiceIndex===correct?' — Correct answer':choiceIndex===selected?' — Your answer':''}</li>`).join('')}</ol><p>${escapeHTML(question.explanation||'')}</p></section>`}).join('')}<button class="primary" id="retryHistoryQuiz" type="button">Try this quiz again</button></article>`}
async function runExplanation(){const topic=needTopic($('#topic'));if(!topic)return;const request=++explanationRequest,button=$('#explainBtn');setBusy(button,true,'Explain this&nbsp; ✦');$('#explanation').innerHTML='<div class="empty"><span class="loader"></span>Finding a clearer way to explain it…</div>';try{const d=await api('/api/explain',{topic,level:$('#level').value,style:learningStyle});if(request!==explanationRequest)return;$('#explanation').innerHTML=explanationMarkup(d,topic);loadProgress();loadChatHistory()}catch(e){if(request===explanationRequest)$('#explanation').innerHTML=`<div class="empty">${escapeHTML(e.message)}</div>`}finally{if(request===explanationRequest)setBusy(button,false,'Explain this&nbsp; ✦')}}
$('#explainBtn').addEventListener('click',runExplanation);

$('#studyBtn').addEventListener('click',async()=>{const topic=needTopic($('#studyTopic'));if(!topic)return;const button=$('#studyBtn');setBusy(button,true,'Build study notes&nbsp; ✦');$('#studyOutput').innerHTML='<div class="empty"><span class="loader"></span>Putting your study set together…</div>';try{const d=await api('/api/study',{topic});$('#studyOutput').innerHTML=studyMarkup(d);loadProgress();loadChatHistory()}catch(e){$('#studyOutput').innerHTML=`<div class="empty">${escapeHTML(e.message)}</div>`}finally{setBusy(button,false,'Build study notes&nbsp; ✦')}});

const svgNamespace='http://www.w3.org/2000/svg';
function conceptSvgElement(name,attributes={}){const element=document.createElementNS(svgNamespace,name);Object.entries(attributes).forEach(([key,value])=>element.setAttribute(key,String(value)));return element}
function conceptLabelLines(label){const lines=[];let line='';for(const word of safeText(label).split(/\s+/)){if(word.length>14){if(line){lines.push(line);line=''}for(let start=0;start<word.length;start+=14)lines.push(word.slice(start,start+14));continue}if(line&&`${line} ${word}`.length>14){lines.push(line);line=word}else line=line?`${line} ${word}`:word}if(line)lines.push(line);if(lines.length>3){lines.length=3;lines[2]=lines[2].slice(0,12)+'…'}return lines}
function renderConceptMap(data){
const output=$('#conceptMapOutput'),svg=conceptSvgElement('svg',{viewBox:'0 0 760 480',class:'concept-map-svg',role:'group','aria-label':`Interactive concept map for ${data.topic}`}),center={x:380,y:240},rx=260,ry=168;
const points=data.concepts.map((concept,index)=>{const angle=-Math.PI/2+Math.PI*2*index/data.concepts.length;return{x:center.x+Math.cos(angle)*rx,y:center.y+Math.sin(angle)*ry,concept,index}});
data.connections.forEach(([from,to],index)=>{const edge=conceptSvgElement('line',{x1:points[from].x,y1:points[from].y,x2:points[to].x,y2:points[to].y,class:'concept-map-edge'});edge.style.animationDelay=`${index*90}ms`;svg.append(edge)});
points.forEach(({x,y})=>{const edge=conceptSvgElement('line',{x1:center.x,y1:center.y,x2:x,y2:y,class:'concept-map-edge'});edge.style.opacity='.55';svg.append(edge)});
const root=conceptSvgElement('g',{class:'concept-map-node concept-map-center',role:'img','aria-label':data.topic});
root.append(conceptSvgElement('circle',{cx:center.x,cy:center.y,r:70}));
const rootText=conceptSvgElement('text',{x:center.x,y:center.y,'text-anchor':'middle','dominant-baseline':'middle'}),rootLabel=safeText(data.topic),shortLabel=rootLabel.length>19?`${rootLabel.slice(0,18)}…`:rootLabel,rootLines=conceptLabelLines(shortLabel);
rootLines.forEach((line,index)=>{const span=conceptSvgElement('tspan',{x:center.x,dy:index===0?`${-(rootLines.length-1)*8}px`:'16px'});span.textContent=line;rootText.append(span)});
root.append(rootText);svg.append(root);
points.forEach(({x,y,concept,index})=>{
const node=conceptSvgElement('g',{class:'concept-map-node',role:'button',tabindex:'0','aria-pressed':'false','aria-label':`${concept.label}: ${concept.description}`});
node.style.animationDelay=`${index*75}ms`;
node.append(conceptSvgElement('circle',{cx:x,cy:y,r:51}));
const text=conceptSvgElement('text',{x,y,'text-anchor':'middle','dominant-baseline':'middle'}),lines=conceptLabelLines(concept.label);
lines.forEach((line,lineIndex)=>{const span=conceptSvgElement('tspan',{x,dy:lineIndex===0?`${-(lines.length-1)*8}px`:'16px'});span.textContent=line;text.append(span)});
node.append(text);svg.append(node)
});
output.innerHTML='';
const canvas=document.createElement('div');canvas.className='concept-map-canvas';
const orbit=document.createElement('div');orbit.className='concept-map-orbit';orbit.setAttribute('aria-hidden','true');
canvas.append(orbit,svg);output.append(canvas);
const details=document.createElement('div');details.className='concept-map-details';
details.innerHTML='<h3 id="conceptMapDetailsTitle">Choose a concept</h3><p id="conceptMapDetailsText">Select any orbiting idea to see what it means and how it connects to the topic.</p>';
output.append(details);
enhanceConceptMapInteractions(data)
}

function enhanceConceptMapInteractions(data){
const output=$('#conceptMapOutput'),svg=output.querySelector('.concept-map-svg'),nodes=[...svg.querySelectorAll('.concept-map-node[role="button"]')],center=svg.querySelector('.concept-map-center'),edges=[...svg.querySelectorAll('.concept-map-edge')],details=output.querySelector('.concept-map-details'),detailsTitle=$('#conceptMapDetailsTitle'),detailsText=$('#conceptMapDetailsText');
center.setAttribute('role','button');center.setAttribute('tabindex','0');center.setAttribute('aria-pressed','false');center.setAttribute('aria-label',`Main topic: ${data.topic}`);
nodes.forEach((node,index)=>{node.dataset.conceptIndex=String(index)});
data.connections.forEach(([from,to],index)=>{edges[index].dataset.from=String(from);edges[index].dataset.to=String(to)});
nodes.forEach((node,index)=>{const edge=edges[data.connections.length+index];edge.dataset.from='-1';edge.dataset.to=String(index)});
const highlight=index=>{edges.forEach(edge=>edge.classList.toggle('is-related',index===-1||Number(edge.dataset.from)===index||Number(edge.dataset.to)===index));nodes.forEach((node,nodeIndex)=>node.setAttribute('aria-pressed',String(nodeIndex===index)));center.setAttribute('aria-pressed',String(index===-1));detailsTitle.textContent=index===-1?data.topic:data.concepts[index].label;detailsText.textContent=index===-1?'This is the main topic. The highlighted spokes connect it to every idea in the map.':data.concepts[index].description};
nodes.forEach((node,index)=>{node.addEventListener('click',()=>highlight(index));node.addEventListener('focus',()=>highlight(index));node.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();highlight(index);return}if(!['ArrowRight','ArrowDown','ArrowLeft','ArrowUp'].includes(event.key))return;event.preventDefault();const step=event.key==='ArrowRight'||event.key==='ArrowDown'?1:-1;nodes[(index+step+nodes.length)%nodes.length].focus()})});
center.addEventListener('click',()=>highlight(-1));center.addEventListener('focus',()=>highlight(-1));
center.addEventListener('keydown',event=>{if(event.key==='Enter'||event.key===' '){event.preventDefault();highlight(-1)}else if(['ArrowRight','ArrowDown'].includes(event.key)){event.preventDefault();nodes[0]?.focus()}});
svg.addEventListener('pointerover',event=>{const node=event.target.closest('.concept-map-node[role="button"]'),nodeKey=node?(node===center?'center':node.dataset.conceptIndex):null;if(node&&!node.matches(':focus')&&nodeKey!==svg.dataset.hoveredNode){svg.dataset.hoveredNode=nodeKey;highlight(node===center?-1:Number(node.dataset.conceptIndex))}});
svg.addEventListener('pointerout',event=>{if(!event.relatedTarget||!svg.contains(event.relatedTarget))delete svg.dataset.hoveredNode});
const exploreButton=document.createElement('button');exploreButton.type='button';exploreButton.textContent='Explore this idea in the learning studio';details.append(exploreButton);
exploreButton.addEventListener('click',()=>{const topic=safeText(detailsTitle.textContent);if(!topic)return;$('#topic').value=topic;$('#explanation').scrollIntoView({behavior:window.matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'center'});runExplanation()});
}
$('#conceptMapBtn').addEventListener('click',async()=>{const topic=needTopic($('#mapTopic'));if(!topic)return;const button=$('#conceptMapBtn'),output=$('#conceptMapOutput');setBusy(button,true,'Mapping the connections…');output.innerHTML='<div class="concept-map-empty"><span class="loader"></span>Finding the ideas and links around your topic…</div>';try{const data=await api('/api/concept-map',{topic});renderConceptMap(data);loadProgress();loadChatHistory()}catch(error){output.innerHTML=`<div class="concept-map-empty">${escapeHTML(error.message)}</div>`}finally{setBusy(button,false,'Build my concept map&nbsp; ✦')}});
$('#quizBtn').addEventListener('click',async()=>{const topic=needTopic($('#quizTopic'));if(!topic)return;const button=$('#quizBtn');setBusy(button,true,'Create my quiz&nbsp; →');$('#quizOutput').innerHTML='<div class="empty"><span class="loader"></span>Creating questions just for you…</div>';try{currentQuiz=await api('/api/quiz',{topic});questionIndex=0;quizScore=0;renderQuestion();loadProgress();loadChatHistory()}catch(e){$('#quizOutput').innerHTML=`<div class="empty">${escapeHTML(e.message)}</div>`}finally{setBusy(button,false,'Create my quiz&nbsp; →')}});

function submitOnEnter(input,button){input.addEventListener('keydown',event=>{if(event.key==='Enter'&&!event.isComposing){event.preventDefault();button.click()}})}
submitOnEnter($('#topic'),$('#explainBtn'));
submitOnEnter($('#quizTopic'),$('#quizBtn'));
submitOnEnter($('#studyTopic'),$('#studyBtn'));
submitOnEnter($('#mapTopic'),$('#conceptMapBtn'));

function renderQuestion(){if(!currentQuiz)return;const qs=currentQuiz.questions;if(questionIndex>=qs.length){finishQuiz();return}const q=qs[questionIndex];$('#quizOutput').innerHTML=`<div class="quiz-footer"><span class="pill">Question ${questionIndex+1} of ${qs.length}</span><span class="pill">${quizScore} correct so far</span></div><div class="quiz-question">${escapeHTML(q.question)}</div><div>${q.choices.map((c,i)=>`<button class="choice" data-answer="${i}">${escapeHTML(c)}</button>`).join('')}</div><div class="feedback" id="quizFeedback" aria-live="polite"></div><div class="quiz-footer"><span></span><button class="primary" id="nextQuestion" style="display:none">${questionIndex===qs.length-1?'See my score':'Next question'} →</button></div>`;document.querySelectorAll('.choice').forEach(b=>b.addEventListener('click',()=>submitAnswer(Number(b.dataset.answer))));$('#nextQuestion').addEventListener('click',()=>{questionIndex++;renderQuestion()})}

async function submitAnswer(answer){const choices=[...document.querySelectorAll('.choice')];if(choices.some(b=>b.disabled))return;choices.forEach(b=>b.disabled=true);try{const result=await api('/api/quiz/check',{quiz_id:currentQuiz.quiz_id,index:questionIndex,answer});choices[result.correct_answer].classList.add('correct');if(!result.correct)choices[answer].classList.add('wrong');else quizScore++;$('#quizFeedback').textContent=(result.correct?'That’s right! ':'Not quite. ')+result.explanation;$('#nextQuestion').style.display='inline-block'}catch(e){choices.forEach(b=>b.disabled=false);toast(e.message)}}

async function finishQuiz(){try{const result=await api('/api/quiz/finish',{quiz_id:currentQuiz.quiz_id});$('#quizOutput').innerHTML=`<div class="empty"><div style="font-size:32px;color:#b5a3ff">✦</div><h3 style="color:white;margin:6px">${result.score} / ${result.total} — nicely done.</h3><p>You explored ${escapeHTML(result.topic)}. Every attempt builds understanding.</p><button class="style-tab" id="again">Try another topic</button></div>`;$('#again').addEventListener('click',()=>{$('#quizTopic').focus();$('#quizOutput').innerHTML='<div class="empty">Your next quiz is ready when you are.</div>'});currentQuiz=null;loadProgress()}catch(e){toast(e.message)}}

async function loadChatHistory(){const list=$('#chatHistoryList');try{const data=await getJSON('/api/history');const labels={explanation:'Explanation',study:'Study notes',quiz:'Quiz',concept_map:'Concept map'};list.innerHTML=data.history.length?data.history.map(item=>`<button class="history-entry" type="button" data-history-id="${item.id}"><span class="history-entry-copy"><span class="history-kind">${labels[item.activity_type]||'Learning'}</span><strong>${escapeHTML(item.topic)}</strong></span><time datetime="${escapeHTML(item.created_at)}">${escapeHTML(new Date(item.created_at).toLocaleString())}</time></button>`).join(''):'<div class="empty">Your learning activities will appear here as you explore.</div>'}catch(error){list.innerHTML=`<div class="empty">${escapeHTML(error.message)}</div>`}}
$('#chatHistoryList').addEventListener('click',async event=>{const button=event.target.closest('[data-history-id]');if(!button)return;button.disabled=true;try{const item=await getJSON(`/api/history/${button.dataset.historyId}`);const behavior=matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth';if(item.activity_type==='explanation'){explanationRequest++;setBusy($('#explainBtn'),false,'Explain this&nbsp; ✦');$('#topic').value=item.topic;$('#level').value=item.level;learningStyle=item.style;document.querySelectorAll('.style-tab[data-style]').forEach(tab=>{tab.classList.toggle('active',tab.dataset.style===learningStyle)});$('#explanation').innerHTML=explanationMarkup(item.result,item.topic);document.getElementById('studio').scrollIntoView({behavior,block:'start'})}else if(item.activity_type==='study'){$('#studyTopic').value=item.topic;$('#studyOutput').innerHTML=studyMarkup(item.result);document.getElementById('tools').scrollIntoView({behavior,block:'start'})}else if(item.activity_type==='concept_map'){$('#mapTopic').value=item.topic;renderConceptMap(item.result);document.getElementById('concept-map').scrollIntoView({behavior,block:'start'})}else if(item.activity_type==='quiz'){$('#quizTopic').value=item.topic;$('#quizOutput').innerHTML=quizHistoryMarkup(item);$('#retryHistoryQuiz').addEventListener('click',()=>$('#quizBtn').click(),{once:true});document.getElementById('tools').scrollIntoView({behavior,block:'start'})}toast('Opened your saved learning activity.')}catch(error){toast(error.message);button.disabled=false}});
let revisionDeck=[],revisionData=null,revisionRetryIds=new Set();
function updateRevisionStats(data){const total=Number(data.total_cards)||0,mastered=Number(data.mastered_cards)||0,mastery=total?Math.round(mastered*100/total):0;$('#revisionMastery').textContent=mastery+'%';$('#revisionMasteryCaption').textContent=total?`${mastered} of ${total} missed questions marked as known.`:'Miss a quiz question and it will appear here for review.';$('#revisionDue').textContent=data.due_count?`${data.due_count} cards due`:'All caught up'}
function renderRevision(){const content=$('#revisionContent');if(!revisionDeck.length){const remaining=Number(revisionData.due_count)||0,title=remaining?'This set is complete!':revisionData.total_cards?'You’re all caught up!':'Your review desk is ready.',message=remaining?`${remaining} more cards are ready whenever you are.`:revisionData.total_cards?'More cards will be ready when it’s time to revisit.':'Miss a quiz question and it will appear here for review.';content.innerHTML=`<div class="revision-complete"><strong>${title}</strong><p>${message}</p>${remaining?'<button class="style-tab" id="reviewMore" type="button">Review the next set&nbsp; →</button>':''}</div>`;$('#reviewMore')?.addEventListener('click',loadRevision);return}const card=revisionDeck[0],choices=Array.isArray(card.choices)?card.choices:[];content.innerHTML=`<div class="revision-session-progress"><div class="revision-meter" role="progressbar" aria-label="Daily review progress" aria-valuemin="0" aria-valuemax="${revisionData.cards.length}" aria-valuenow="${revisionData.cards.length-revisionDeck.length}"><span style="width:${Math.round((revisionData.cards.length-revisionDeck.length)*100/revisionData.cards.length)}%"></span></div><p>Card ${revisionData.cards.length-revisionDeck.length+1} of ${revisionData.cards.length}${revisionDeck.length>revisionData.cards.length?' · one more look':''} &nbsp;·&nbsp; ${escapeHTML(card.topic)}</p></div><button class="revision-flashcard" id="revisionFlip" type="button" aria-pressed="false" aria-label="Show the answer"><span class="revision-card-inner"><span class="revision-card-face front"><span class="section-label">Try to remember</span><strong>${escapeHTML(card.question)}</strong><span class="revision-card-hint">Tap the card to reveal the answer</span></span><span class="revision-card-face back"><span class="section-label">The answer</span><strong>${escapeHTML(choices[card.correct_answer]||'')}</strong><p>${escapeHTML(card.explanation||'')}</p><p class="revision-card-hint">You chose: ${escapeHTML(choices[card.user_answer]||'')}</p></span></span></button><div class="revision-actions"><button class="style-tab revision-again" id="revisionAgain" type="button">↻ Review again</button><button class="primary revision-got-it" id="revisionGotIt" type="button">Got it&nbsp; ✓</button></div>`;$('#revisionFlip').addEventListener('click',event=>{const flipped=event.currentTarget.classList.toggle('is-flipped');event.currentTarget.setAttribute('aria-pressed',String(flipped));event.currentTarget.setAttribute('aria-label',flipped?'Show the question':'Show the answer')});$('#revisionAgain').addEventListener('click',()=>reviewRevisionCard('again'));$('#revisionGotIt').addEventListener('click',()=>reviewRevisionCard('got_it'))}
async function loadRevision(){try{revisionData=await getJSON('/api/revision','Could not load your revision cards.');revisionDeck=[...revisionData.cards];revisionRetryIds=new Set();updateRevisionStats(revisionData);renderRevision();const topics=revisionData.weak_topics||[];$('#weakTopicList').innerHTML=topics.length?topics.map(topic=>`<button class="weak-topic" type="button" data-revision-topic="${escapeHTML(topic.topic)}"><strong>${escapeHTML(topic.topic)}</strong><span>${Number(topic.mastery)||0}%</span><small>${topic.quizzes} ${topic.quizzes===1?'quiz':'quizzes'} · based on quiz accuracy</small></button>`).join(''):'<div class="empty">Take a quiz to discover which topic could use another look.</div>'}catch(error){$('#revisionDue').textContent='Could not load';$('#revisionContent').innerHTML=`<div class="empty">${escapeHTML(error.message)}</div>`;$('#weakTopicList').innerHTML=`<div class="empty">${escapeHTML(error.message)}</div>`}}
async function reviewRevisionCard(action){const card=revisionDeck[0];if(!card)return;const buttons=document.querySelectorAll('.revision-actions button');buttons.forEach(button=>button.disabled=true);try{const stats=await api('/api/revision/review',{card_id:card.id,action});revisionData={...revisionData,...stats};revisionDeck.shift();if(action==='again'&&!revisionRetryIds.has(card.id)){revisionRetryIds.add(card.id);revisionDeck.push(card)}updateRevisionStats(revisionData);renderRevision()}catch(error){buttons.forEach(button=>button.disabled=false);toast(error.message)}}
$('#weakTopicList').addEventListener('click',event=>{const button=event.target.closest('[data-revision-topic]');if(!button)return;$('#quizTopic').value=button.dataset.revisionTopic;document.getElementById('tools').scrollIntoView({behavior:matchMedia('(prefers-reduced-motion: reduce)').matches?'auto':'smooth',block:'start'});$('#quizTopic').focus({preventScroll:true});toast(`Ready to practise ${button.dataset.revisionTopic}.`)});
async function loadProgress(){try{const response=await fetch('/api/progress');if(!response.ok)throw Error('Could not load your progress.');const data=await response.json();$('#activityCount').textContent=data.activities;$('#quizCount').textContent=data.quizzes;$('#accuracy').textContent=data.accuracy+'%';const maxSessions=Math.max(1,...data.topics.map(topic=>Number(topic.sessions)||0));$('#topicList').innerHTML=data.topics.length?data.topics.map(topic=>{const sessions=Number(topic.sessions)||0,mastery=topic.mastery===null||topic.mastery===undefined?null:Number(topic.mastery),percent=mastery===null?Math.round(sessions*100/maxSessions):mastery,label=mastery===null?`${sessions} ${sessions===1?'session':'sessions'} · take a quiz to track mastery`:`${mastery}% mastery · ${sessions} ${sessions===1?'session':'sessions'}`;return `<div class="topic-row"><span>${escapeHTML(topic.topic)}</span><span>${label}</span><div class="topic-history-bar" role="progressbar" aria-label="${escapeHTML(topic.topic)} ${mastery===null?'learning activity':'quiz mastery'}" aria-valuemin="0" aria-valuemax="${mastery===null?maxSessions:100}" aria-valuenow="${mastery===null?sessions:mastery}"><span style="width:${percent}%"></span></div></div>`}).join(''):'<div class="empty">Your learning history will appear here as you explore.</div>'}catch(error){$('#topicList').innerHTML=`<div class="empty">${escapeHTML(error.message)}</div>`}await loadRevision()}loadProgress();loadChatHistory();

const observer=new IntersectionObserver(entries=>entries.forEach(e=>{if(e.isIntersecting){e.target.classList.add('visible');observer.unobserve(e.target)}}),{threshold:.12});document.querySelectorAll('.reveal').forEach(el=>observer.observe(el));
if('serviceWorker' in navigator){window.addEventListener('load',()=>navigator.serviceWorker.register('/service-worker.js').catch(error=>console.error('Service worker registration failed:',error)))}
</script>
</body>
</html>'''


PWA_ICON = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512">
<rect width="512" height="512" rx="112" fill="#100d24"/>
<path d="M96 145c59-15 115-4 160 33v205c-45-37-101-48-160-33V145Zm320 0c-59-15-115-4-160 33v205c45-37 101-48 160-33V145Z" fill="#426f9d" stroke="#faf5e9" stroke-linejoin="round" stroke-width="18"/>
<path d="M364 94v76m-38-38h76" fill="none" stroke="#ffe28a" stroke-linecap="round" stroke-width="20"/>
</svg>'''

SERVICE_WORKER = r"""
const CACHE_NAME = 'studyease-offline-v1';
const OFFLINE_PATH = '/offline-fallback';
const OFFLINE_PAGE = `<!doctype html>
<html lang="en">
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#100d24">
<title>StuDyEaSe — Offline</title>
<style>
body{margin:0;min-height:100vh;display:grid;place-items:center;background:#100d24;color:#faf5e9;font:16px/1.6 system-ui,sans-serif;text-align:center}
main{max-width:28rem;padding:2rem}h1{font-size:2rem}p{color:#d7d1e7}a{color:#ffe28a}
</style>
<main><h1>You’re offline</h1><p>Reconnect to the internet to use your learning studio, quizzes, and saved progress.</p><a href="/">Try again</a></main>
</html>`;

self.addEventListener('install', event => {
  event.waitUntil((async () => {
    const cache = await caches.open(CACHE_NAME);
    await cache.put(OFFLINE_PATH, new Response(OFFLINE_PAGE, {
      headers: { 'Content-Type': 'text/html; charset=utf-8' }
    }));
    await self.skipWaiting();
  })());
});

self.addEventListener('activate', event => {
  event.waitUntil((async () => {
    const keys = await caches.keys();
    await Promise.all(keys.filter(key => key.startsWith('studyease-offline-') && key !== CACHE_NAME)
      .map(key => caches.delete(key)));
    await self.clients.claim();
  })());
});

self.addEventListener('fetch', event => {
  if (event.request.method !== 'GET' || event.request.mode !== 'navigate') return;
  event.respondWith(fetch(event.request).catch(async () => {
    const cache = await caches.open(CACHE_NAME);
    return cache.match(OFFLINE_PATH);
  }));
});
"""


@app.get("/manifest.webmanifest")
def pwa_manifest():
	response = jsonify({
		"name": "StuDyEaSe — Understand EASY. Learn More.",
		"short_name": "StuDyEaSe",
		"description": "Personal AI learning studio with explanations, quizzes, and study tools.",
		"start_url": "/",
		"scope": "/",
		"display": "standalone",
		"background_color": "#100d24",
		"theme_color": "#100d24",
		"icons": [
			{"src": "/app-icon.svg", "sizes": "192x192", "type": "image/svg+xml", "purpose": "any maskable"},
			{"src": "/app-icon.svg", "sizes": "512x512", "type": "image/svg+xml", "purpose": "any maskable"},
		],
	})
	response.content_type = "application/manifest+json"
	return response


@app.get("/app-icon.svg")
def pwa_icon():
	return Response(PWA_ICON, mimetype="image/svg+xml")


@app.get("/service-worker.js")
def pwa_service_worker():
	response = Response(SERVICE_WORKER, mimetype="application/javascript")
	response.headers["Cache-Control"] = "no-cache"
	response.headers["Service-Worker-Allowed"] = "/"
	return response


@app.get("/")
def home():
	return render_template_string(PAGE, csrf_token=session["csrf_token"])


init_db()


if __name__ == "__main__":
	app.run(host=os.environ.get("HOST", "127.0.0.1"), port=int(os.environ.get("PORT", "5000")), debug=False)