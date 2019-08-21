defmodule AsteroidWeb.OTPEmail do
  use Bamboo.Phoenix, view: AsteroidWeb.EmailView

  def otp_email(email, otp) do
    base_email()
    |> to(email)
    |> subject("Your authorization code")
    |> assign(:otp, otp)
    |> render(:email)
  end

  defp base_email do
    Bamboo.Email.new_email()
    |> from("Asteroid <asteroid@repentant-brief-fishingcat.gigalixirapp.com>")
    |> put_html_layout({AsteroidWeb.LayoutView, "email.html"})
  end
end
