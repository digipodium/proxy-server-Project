from app import app
import json

def test_dashboard():
    with app.test_client() as client:
        # Mock session
        with client.session_transaction() as sess:
            sess['user'] = 'testadmin'
        
        response = client.get('/dashboard')
        print(f"Status Code: {response.status_code}")
        if response.status_code == 500:
            try:
                data = json.loads(response.data)
                print(f"Error Message: {data.get('message')}")
            except:
                print("Response is not JSON. Likely a template error or low-level crash.")
                print(response.data[:500])
        else:
            print("Dashboard reached successfully (in test environment).")

if __name__ == "__main__":
    test_dashboard()
