# sdn_ddos_backend
<img width="898" height="580" alt="image" src="https://github.com/user-attachments/assets/f5432ea0-4577-4b99-a712-6852ede872ce" />

### Person A (ML Specialist):

-You will work almost exclusively inside the /notebooks folder.
-Your main file will be model_development.ipynb.
-When you have trained and saved your final model, you will place the ddos_model.joblib file inside the /models folder.

### Person B (Network Specialist):

-You will work inside the /sdn_app folder.
-Your main file will be the Ryu application, realtime_detector.py.
-You will also create the testing scripts and place them in the /scripts folder.
-This structure keeps the experimental code (notebooks), the final application code (sdn_app), and the saved ML model (models) perfectly organized.

### When it's time for integration, the main application in /sdn_app will simply load the model from the /models folder. This makes coupling the work clean and straightforward.
