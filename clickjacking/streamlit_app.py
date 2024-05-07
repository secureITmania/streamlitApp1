import streamlit as st
import requests
from urllib.parse import urlparse

def parse_csp(csp_header):
    directives = {}
    for part in csp_header.split(';'):
        if ' ' in part:
            key, value = part.strip().split(' ', 1)
            directives[key.lower()] = value.strip()
        else:
            directives[part.lower()] = ''
    return directives

def check_clickjacking(url):
    try:
        response = requests.get(url)
        headers = response.headers
        x_frame_options = headers.get('X-Frame-Options', None)
        csp = headers.get('Content-Security-Policy', None)

        if x_frame_options:
            return f"X-Frame-Options set to: {x_frame_options}", False
        elif csp:
            csp_directives = parse_csp(csp)
            frame_ancestors = csp_directives.get('frame-ancestors', None)
            #print(frame_ancestors)
            if frame_ancestors:
                if 'none' in frame_ancestors or 'self' in frame_ancestors or "http" in frame_ancestors:
                    return "CSP frame-ancestors set to prevent framing.", False
                else:
                    return "CSP frame-ancestors allows framing from all domains.", True
            else:
                return "CSP is set but does not specify frame-ancestors.", True
        else:
            return "No clickjacking protection detected!", True
    except requests.exceptions.RequestException as e:
        return f"Failed to retrieve URL due to: {e}", None

def main():
    st.title('Clickjacking Vulnerability Checker')
    url = st.text_input('Enter the URL to check', '')

    if url:
        parsed_url = urlparse(url)
        if not parsed_url.scheme:
            url = 'http://' + url
        message, vulnerable = check_clickjacking(url)
        st.write(message)
        if vulnerable is True:
            st.markdown(f"### Vulnerable! Try embedding `{url}` in an iframe:")
            st.markdown(f'<iframe src="{url}" width="100%" height="300"></iframe>', unsafe_allow_html=True)
        elif vulnerable is False:
            st.markdown("### Not Vulnerable")
        elif vulnerable is None:
            st.markdown("### Error in URL retrieval")

if __name__ == "__main__":
    main()
