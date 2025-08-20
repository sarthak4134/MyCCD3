import boto3
from flask import Flask, render_template

app = Flask(__name__)

S3_BUCKET = 'sarthakdasstorage1'
AWS_REGION = 'eu-north-1'

s3_client = boto3.client('s3', region_name=AWS_REGION)

@app.route('/')
def home():
    video_urls = []
    try:
        response = s3_client.list_objects_v2(Bucket=S3_BUCKET)
        
        if 'Contents' in response:
            video_files = [
                obj['Key'] for obj in response['Contents'] 
                if obj['Key'].lower().endswith(('.mp4', '.mov', '.avi'))
            ]

            for video_key in video_files:
                url = s3_client.generate_presigned_url(
                    'get_object',
                    Params={'Bucket': S3_BUCKET, 'Key': video_key},
                    ExpiresIn=3600
                )
                video_urls.append({'key': video_key, 'url': url})

    except Exception as e:
        print(f"Error fetching from S3: {e}")
        pass

    return render_template('index.html', videos=video_urls)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)