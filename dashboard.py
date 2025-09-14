from flask import Flask, render_template
import sqlite3
import pandas as pd

app = Flask(__name__)

DB_FILE = "sus.db"


def get_data():
    conn = sqlite3.connect(DB_FILE)
    df = pd.read_sql_query("SELECT * FROM attempts", conn)
    conn.close()
    return df


@app.route("/")
def dashboard():
    df = get_data()

    # Summary metrics
    total_alerts = len(df)
    top_ips = df["ip"].value_counts().head(5).to_dict()
    reasons = df["reason"].value_counts().to_dict()

    return render_template(
        "dashboard.html",
        tables=df.to_dict(orient="records"),
        total_alerts=total_alerts,
        top_ips=top_ips,
        reasons=reasons,
    )


if __name__ == "__main__":
    app.run(debug=True)
