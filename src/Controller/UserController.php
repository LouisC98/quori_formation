<?php

namespace App\Controller;

use App\Entity\User;
use App\Form\UserType;
use Doctrine\ORM\EntityManagerInterface;
use Sensio\Bundle\FrameworkExtraBundle\Configuration\IsGranted;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\Form\Extension\Core\Type\PasswordType;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\PasswordHasher\Hasher\UserPasswordHasherInterface;
use Symfony\Component\Routing\Annotation\Route;


#[Route('/user')]
class UserController extends AbstractController
{
    #[Route('/', name: 'current_user')]
    #[IsGranted('IS_AUTHENTICATED_FULLY')]
    public function currentUserProfile(Request $request, UserPasswordHasherInterface $passwordHasheur, EntityManagerInterface $em): Response
    {
        /**
         * @var User
         */
        $user = $this->getUser();

        $userFormProfile = $this->createForm(UserType::class, $user);
        $userFormProfile->remove('password');
        $userFormProfile->add(
            'newPassword',
            PasswordType::class,
            [
                'label' => 'Nouveau mot de passe',
                'required' => false
            ]
        );
        $userFormProfile->handleRequest($request);

        if ($userFormProfile->isSubmitted() && $userFormProfile->isValid()) {
            $newPassword = $user->getNewPassword();

            if ($newPassword) {
                $hash = $passwordHasheur->hashPassword($user, $newPassword);
                $user->setPassword($hash);
            }

            $em->flush();
            $this->addFlash('success', 'Modifications enregistrées');
        }

        return $this->render('user/index.html.twig', [
            'form' => $userFormProfile->createView()
        ]);
    }

    #[Route('/questions', name: 'show_questions')]
    #[IsGranted('IS_AUTHENTICATED_REMEMBERED')]
    public function showQuestions(): Response
    {

        return $this->render('user/show_questions.html.twig');
    }

    #[Route('/comments', name: 'show_comments')]
    #[IsGranted('IS_AUTHENTICATED_REMEMBERED')]
    public function showComments(): Response
    {

        return $this->render('user/show_comments.html.twig');
    }

    #[Route('/{id}', name: 'user')]
    #[IsGranted('IS_AUTHENTICATED_REMEMBERED')]
    public function userProfile(User $user): Response
    {
        $currentUser = $this->getUser();

        if ($user === $currentUser) {
            return $this->redirectToRoute('current_user');
        }

        return $this->render('user/show.html.twig', [
            'user' => $user
        ]);
    }

}
